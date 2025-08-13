#!/usr/bin/env ruby

# LEVIPENTBOX - Outil de Pentest Réseau Ultra-Avancé
# Version améliorée de Pentbox avec fonctionnalités avancées

require 'optparse'
require 'json'
require 'fileutils'
require 'time'
require 'open3'
require 'socket'
require 'net/http'
require 'net/https'
require 'uri'
require 'thread'
require 'securerandom'

class LeviPentbox
  attr_reader :config, :results, :targets
  
  def initialize
    @config = {
      interface: 'eth0',
      target: nil,
      port_range: '1-1000',
      timeout: 30,
      threads: 10,
      output_dir: 'levipentbox_results',
      verbose: false,
      aggressive: false
    }
    @results = {} # Initialize results as a hash
    @targets = []
    @attack_processes = []
  end
  
  def parse_arguments
    OptionParser.new do |opts|
      opts.banner = "Usage: levipentbox.rb [OPTIONS]"
      
      opts.on('-t', '--target TARGET', 'Cible (IP ou domaine)') do |v|
        @config[:target] = v
      end
      
      opts.on('-i', '--interface INTERFACE', 'Interface réseau') do |v|
        @config[:interface] = v
      end
      
      opts.on('-p', '--ports RANGE', 'Plage de ports (ex: 1-1000)') do |v|
        @config[:port_range] = v
      end
      
      opts.on('--threads NUM', Integer, 'Nombre de threads') do |v|
        @config[:threads] = v
      end
      
      opts.on('-o', '--output DIR', 'Répertoire de sortie') do |v|
        @config[:output_dir] = v
      end
      
      opts.on('-v', '--verbose', 'Mode verbeux') do
        @config[:verbose] = true
      end
      
      opts.on('-a', '--aggressive', 'Mode agressif') do
        @config[:aggressive] = true
      end
      
      opts.on('-h', '--help', 'Afficher cette aide') do
        puts opts
        exit
      end
    end.parse!
    
    validate_config
  end
  
  def validate_config
    unless @config[:target]
      puts "[-] Erreur: Cible requise (-t ou --target)"
      exit 1
    end
    
    unless Dir.exist?(@config[:output_dir])
      FileUtils.mkdir_p(@config[:output_dir])
    end
  end
  
  def log(message, level = 'INFO')
    timestamp = Time.now.strftime('%Y-%m-%d %H:%M:%S')
    puts "[#{timestamp}] [#{level}] #{message}"
  end
  
  def run_command(command, timeout = 30)
    log("Exécution: #{command}") if @config[:verbose]
    
    begin
      stdout, stderr, status = Open3.capture3(command, timeout: timeout)
      
      if status.success?
        log("Commande réussie: #{command}") if @config[:verbose]
        return { success: true, stdout: stdout, stderr: stderr }
      else
        log("Commande échouée: #{command}", 'ERROR')
        return { success: false, stdout: stdout, stderr: stderr, exit_code: status.exitstatus }
      end
    rescue => e
      log("Exception lors de l'exécution: #{e.message}", 'ERROR')
      return { success: false, error: e.message }
    end
  end
  
  def port_scan_advanced
    log("🔍 Scan de ports avancé")
    
    start_port, end_port = parse_port_range(@config[:port_range])
    
    open_ports = []
    threads = []
    queue = Queue.new
    
    # Ajouter les ports à la queue
    (start_port..end_port).each { |port| queue << port }
    
    # Créer les threads de scan
    @config[:threads].times do
      threads << Thread.new do
        while port = queue.pop(true) rescue nil
          if scan_port(@config[:target], port)
            open_ports << port
            log("Port #{port} ouvert sur #{@config[:target]}")
          end
        end
      end
    end
    
    # Attendre la fin des threads
    threads.each(&:join)
    
    log("Scan terminé: #{open_ports.length} ports ouverts")
    return open_ports
  end
  
  def parse_port_range(range)
    if range.include?('-')
      start_port, end_port = range.split('-').map(&:to_i)
    else
      start_port = end_port = range.to_i
    end
    [start_port, end_port]
  end
  
  def scan_port(host, port)
    begin
      socket = TCPSocket.new(host, port)
      socket.close
      return true
    rescue
      return false
    end
  end
  
  def service_detection(host, ports)
    log("🔍 Détection des services")
    
    services = {}
    ports.each do |port|
      service = detect_service(host, port)
      services[port] = service if service
    end
    
    return services
  end
  
  def detect_service(host, port)
    common_services = {
      21 => 'FTP',
      22 => 'SSH',
      23 => 'Telnet',
      25 => 'SMTP',
      53 => 'DNS',
      80 => 'HTTP',
      110 => 'POP3',
      143 => 'IMAP',
      443 => 'HTTPS',
      445 => 'SMB',
      993 => 'IMAPS',
      995 => 'POP3S',
      3306 => 'MySQL',
      5432 => 'PostgreSQL',
      8080 => 'HTTP-Proxy'
    }
    
    return common_services[port] || 'Unknown'
  end
  
  def vulnerability_scan(host, services)
    log("🔍 Scan de vulnérabilités")
    
    vulnerabilities = []
    
    services.each do |port, service|
      case service
      when 'HTTP', 'HTTPS'
        vulns = scan_web_vulnerabilities(host, port)
        vulnerabilities.concat(vulns)
      when 'SSH'
        vulns = scan_ssh_vulnerabilities(host, port)
        vulnerabilities.concat(vulns)
      when 'FTP'
        vulns = scan_ftp_vulnerabilities(host, port)
        vulnerabilities.concat(vulns)
      end
    end
    
    return vulnerabilities
  end
  
  def scan_web_vulnerabilities(host, port)
    vulns = []
    protocol = port == 443 ? 'https' : 'http'
    
    begin
      uri = URI("#{protocol}://#{host}:#{port}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (protocol == 'https')
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      
      # Test des vulnérabilités communes
      response = http.get('/')
      
      # Vérifier les en-têtes de sécurité
      unless response['X-Frame-Options']
        vulns << { type: 'Missing Security Headers', port: port, details: 'X-Frame-Options header missing' }
      end
      
      unless response['X-Content-Type-Options']
        vulns << { type: 'Missing Security Headers', port: port, details: 'X-Content-Type-Options header missing' }
      end
      
      # Test des méthodes HTTP
      response = http.request(Net::HTTP::Options.new('/'))
      if response['Allow']&.include?('TRACE')
        vulns << { type: 'HTTP TRACE Method', port: port, details: 'TRACE method enabled' }
      end
      
    rescue => e
      log("Erreur scan web: #{e.message}", 'WARNING')
    end
    
    return vulns
  end
  
  def scan_ssh_vulnerabilities(host, port)
    vulns = []
    
    # Test de la version SSH
    result = run_command("nmap -p #{port} -sV #{host}", 30)
    if result[:success]
      if result[:stdout].include?('SSH')
        vulns << { type: 'SSH Service', port: port, details: 'SSH service detected' }
      end
    end
    
    return vulns
  end
  
  def scan_ftp_vulnerabilities(host, port)
    vulns = []
    
    # Test FTP anonyme
    result = run_command("nmap -p #{port} --script ftp-anon #{host}", 30)
    if result[:success] && result[:stdout].include?('Anonymous FTP login allowed')
      vulns << { type: 'Anonymous FTP', port: port, details: 'Anonymous FTP login allowed' }
    end
    
    return vulns
  end
  
  def brute_force_attack(host, services)
    log("🔓 Attaques de brute force")
    
    results = {}
    
    services.each do |port, service|
      case service
      when 'SSH'
        results[port] = brute_force_ssh(host, port)
      when 'FTP'
        results[port] = brute_force_ftp(host, port)
      when 'HTTP'
        results[port] = brute_force_web(host, port)
      end
    end
    
    return results
  end
  
  def brute_force_ssh(host, port)
    log("Tentative de brute force SSH sur #{host}:#{port}")
    
    # Utiliser hydra pour le brute force SSH
    wordlist = '/usr/share/wordlists/rockyou.txt'
    return { success: false, error: 'Wordlist non trouvée' } unless File.exist?(wordlist)
    
    command = "hydra -L /usr/share/wordlists/users.txt -P #{wordlist} #{host} ssh -t #{@config[:threads]}"
    result = run_command(command, 300)
    
    if result[:success] && result[:stdout].include?('login:')
      return { success: true, credentials: extract_credentials(result[:stdout]) }
    else
      return { success: false, error: 'Aucune credential trouvée' }
    end
  end
  
  def brute_force_ftp(host, port)
    log("Tentative de brute force FTP sur #{host}:#{port}")
    
    wordlist = '/usr/share/wordlists/rockyou.txt'
    return { success: false, error: 'Wordlist non trouvée' } unless File.exist?(wordlist)
    
    command = "hydra -L /usr/share/wordlists/users.txt -P #{wordlist} #{host} ftp -t #{@config[:threads]}"
    result = run_command(command, 300)
    
    if result[:success] && result[:stdout].include?('login:')
      return { success: true, credentials: extract_credentials(result[:stdout]) }
    else
      return { success: false, error: 'Aucune credential trouvée' }
    end
  end
  
  def brute_force_web(host, port)
    log("Tentative de brute force web sur #{host}:#{port}")
    
    # Test des chemins communs
    common_paths = ['/admin', '/login', '/wp-admin', '/phpmyadmin', '/cpanel']
    protocol = port == 443 ? 'https' : 'http'
    
    found_paths = []
    common_paths.each do |path|
      begin
        uri = URI("#{protocol}://#{host}:#{port}#{path}")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (protocol == 'https')
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        
        response = http.get(path)
        if response.code != '404'
          found_paths << { path: path, code: response.code }
        end
      rescue
        next
      end
    end
    
    return { success: found_paths.any?, paths: found_paths }
  end
  
  def extract_credentials(output)
    credentials = []
    lines = output.split("\n")
    
    lines.each do |line|
      if line.include?('login:') && line.include?('password:')
        parts = line.split
        if parts.length >= 4
          credentials << { user: parts[2], password: parts[4] }
        end
      end
    end
    
    return credentials
  end
  
  def network_analysis(host)
    log("🌐 Analyse réseau avancée")
    
    analysis = {
      hostname: resolve_hostname(host),
      os_detection: detect_os(host),
      traceroute: perform_traceroute(host),
      dns_enumeration: enumerate_dns(host),
      whois_info: get_whois_info(host)
    }
    
    return analysis
  end
  
  def resolve_hostname(host)
    begin
      return Socket.gethostbyname(host)[0]
    rescue
      return host
    end
  end
  
  def detect_os(host)
    result = run_command("nmap -O #{host}", 60)
    if result[:success]
      return result[:stdout]
    else
      return 'OS detection failed'
    end
  end
  
  def perform_traceroute(host)
    result = run_command("traceroute #{host}", 60)
    if result[:success]
      return result[:stdout]
    else
      return 'Traceroute failed'
    end
  end
  
  def enumerate_dns(host)
    dns_info = {}
    
    # Résolution DNS
    begin
      dns_info[:a] = Socket.gethostbyname(host)[3..-1].map(&:unpack, 'C4').join('.')
    rescue
      dns_info[:a] = 'Failed'
    end
    
    # Test des enregistrements MX
    result = run_command("nslookup -type=mx #{host}", 30)
    if result[:success]
      dns_info[:mx] = result[:stdout]
    end
    
    return dns_info
  end
  
  def get_whois_info(host)
    result = run_command("whois #{host}", 60)
    if result[:success]
      return result[:stdout]
    else
      return 'Whois failed'
    end
  end
  
  def generate_report
    log("📊 Génération du rapport Levipentbox")
    
    report = {
      scan_time: Time.now.iso8601,
      target: @config[:target],
      configuration: @config,
      results: @results,
      summary: generate_summary
    }
    
    # Rapport JSON
    json_file = File.join(@config[:output_dir], "levipentbox_report.json")
    File.write(json_file, JSON.pretty_generate(report))
    
    # Rapport HTML
    html_file = generate_html_report(report)
    
    log("Rapport généré: #{json_file} et #{html_file}")
    return { json: json_file, html: html_file }
  end
  
  def generate_summary
    summary = {
      ports_scanned: @results[:ports]&.length || 0,
      services_found: @results[:services]&.length || 0,
      vulnerabilities_found: @results[:vulnerabilities]&.length || 0,
      brute_force_success: @results[:brute_force]&.select { |k, v| v[:success] }&.length || 0
    }
    
    return summary
  end
  
  def generate_html_report(report)
    html_content = <<~HTML
      <!DOCTYPE html>
      <html lang="fr">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>LEVIPENTBOX - Rapport de Pentest</title>
          <style>
              * { margin: 0; padding: 0; box-sizing: border-box; }
              body { font-family: 'Courier New', monospace; background: #1a1a1a; color: #00ff00; line-height: 1.6; }
              .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
              .header { background: #2d2d2d; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px; border: 2px solid #00ff00; }
              .header h1 { font-size: 3em; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.5); }
              .section { background: #2a2a2a; padding: 25px; border-radius: 8px; margin-bottom: 25px; border: 1px solid #00ff00; }
              .section h2 { color: #00ff00; margin-bottom: 20px; font-size: 1.8em; }
              .vulnerability { background: #333; padding: 15px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #ff0000; }
              .service { background: #333; padding: 10px; border-radius: 5px; margin: 5px 0; }
              .success { color: #00ff00; }
              .warning { color: #ffff00; }
              .error { color: #ff0000; }
              .timestamp { color: #888; font-size: 0.9em; }
          </style>
      </head>
      <body>
          <div class="container">
              <div class="header">
                  <h1>🔓 LEVIPENTBOX</h1>
                  <p>Rapport de Pentest Réseau Ultra-Avancé</p>
                  <p class="timestamp">Généré le: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}</p>
              </div>
              
              <div class="section">
                  <h2>🎯 Cible</h2>
                  <p><strong>Host:</strong> #{report[:target]}</p>
                  <p><strong>Interface:</strong> #{report[:configuration][:interface]}</p>
                  <p><strong>Ports:</strong> #{report[:configuration][:port_range]}</p>
              </div>
              
              <div class="section">
                  <h2>📊 Résumé</h2>
                  <p><strong>Ports scannés:</strong> #{report[:summary][:ports_scanned]}</p>
                  <p><strong>Services trouvés:</strong> #{report[:summary][:services_found]}</p>
                  <p><strong>Vulnérabilités:</strong> #{report[:summary][:vulnerabilities_found]}</p>
                  <p><strong>Brute force réussis:</strong> #{report[:summary][:brute_force_success]}</p>
              </div>
    HTML
    
    # Ajouter les services
    if report[:results][:services]
      html_content += "<div class='section'><h2>🔍 Services Détectés</h2>"
      report[:results][:services].each do |port, service|
        html_content += "<div class='service'><strong>Port #{port}:</strong> #{service}</div>"
      end
      html_content += "</div>"
    end
    
    # Ajouter les vulnérabilités
    if report[:results][:vulnerabilities]
      html_content += "<div class='section'><h2>⚠️ Vulnérabilités</h2>"
      report[:results][:vulnerabilities].each do |vuln|
        html_content += "<div class='vulnerability'>"
        html_content += "<strong>Type:</strong> #{vuln[:type]}<br>"
        html_content += "<strong>Port:</strong> #{vuln[:port]}<br>"
        html_content += "<strong>Détails:</strong> #{vuln[:details]}"
        html_content += "</div>"
      end
      html_content += "</div>"
    end
    
    html_content += <<~HTML
              <div class="section">
                  <h2>🔓 Résultats Brute Force</h2>
                  <p>Consultez le rapport JSON pour les détails complets.</p>
              </div>
              
              <div class="section">
                  <h2>🌐 Analyse Réseau</h2>
                  <p>Consultez le rapport JSON pour les détails complets.</p>
              </div>
          </div>
      </body>
      </html>
    HTML
    
    html_file = File.join(@config[:output_dir], "levipentbox_report.html")
    File.write(html_file, html_content)
    
    return html_file
  end
  
  def run_complete_pentest
    log("🚀 DÉBUT DU PENTEST LEVIPENTBOX")
    
    begin
      # 1. Scan de ports
      ports = port_scan_advanced
      @results[:ports] = ports
      
      # 2. Détection des services
      services = service_detection(@config[:target], ports)
      @results[:services] = services
      
      # 3. Scan de vulnérabilités
      vulnerabilities = vulnerability_scan(@config[:target], services)
      @results[:vulnerabilities] = vulnerabilities
      
      # 4. Brute force (si mode agressif)
      if @config[:aggressive]
        brute_results = brute_force_attack(@config[:target], services)
        @results[:brute_force] = brute_results
      end
      
      # 5. Analyse réseau
      network_info = network_analysis(@config[:target])
      @results[:network_analysis] = network_info
      
      # 6. Génération du rapport
      report_files = generate_report
      
      log("🎉 PENTEST LEVIPENTBOX TERMINÉ AVEC SUCCÈS!")
      log("📊 Rapports générés:")
      log("   JSON: #{report_files[:json]}")
      log("   HTML: #{report_files[:html]}")
      
      return true
      
    rescue => e
      log("Erreur lors du pentest: #{e.message}", 'ERROR')
      log(e.backtrace.join("\n"), 'ERROR')
      return false
    end
  end
end

# Point d'entrée principal
if __FILE__ == $0
  begin
    pentbox = LeviPentbox.new
    pentbox.parse_arguments
    success = pentbox.run_complete_pentest
    
    if success
      puts "\n🎉 LEVIPENTBOX terminé avec succès!"
      puts "📊 Consultez les rapports dans le dossier: #{pentbox.config[:output_dir]}"
    else
      puts "\n💥 LEVIPENTBOX a rencontré des erreurs"
      exit 1
    end
  rescue => e
    puts "[-] Erreur fatale: #{e.message}"
    puts e.backtrace.join("\n")
    exit 1
  end
end
