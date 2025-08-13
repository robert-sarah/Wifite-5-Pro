#!/usr/bin/env ruby

# LEVIPENTBOX - Module de Scan Réseau
# Scan ultra-rapide et précis des réseaux

require 'socket'
require 'thread'
require 'timeout'
require 'json'

class NetworkScanner
  attr_reader :targets, :results
  
  def initialize(interface, output_dir)
    @interface = interface
    @output_dir = output_dir
    @targets = []
    @results = {}
  end
  
  def log(message, level = 'INFO')
    timestamp = Time.now.strftime('%Y-%m-%d %H:%M:%S')
    puts "[#{timestamp}] [#{level}] #{message}"
  end
  
  def scan_network_range(network_range, threads = 10)
    log("🔍 Scan du réseau: #{network_range}")
    
    hosts = generate_host_list(network_range)
    alive_hosts = []
    
    queue = Queue.new
    hosts.each { |host| queue << host }
    
    thread_pool = []
    threads.times do
      thread_pool << Thread.new do
        while host = queue.pop(true) rescue nil
          if ping_host(host)
            alive_hosts << host
            log("Host actif trouvé: #{host}")
          end
        end
      end
    end
    
    thread_pool.each(&:join)
    
    @targets = alive_hosts
    log("Scan terminé: #{alive_hosts.length} hosts actifs")
    return alive_hosts
  end
  
  def generate_host_list(network_range)
    hosts = []
    
    if network_range.include?('/')
      # Notation CIDR
      base_ip, mask = network_range.split('/')
      mask = mask.to_i
      
      # Calculer le nombre d'hôtes
      num_hosts = 2**(32 - mask) - 2
      
      # Générer les IPs
      base_parts = base_ip.split('.').map(&:to_i)
      base_int = (base_parts[0] << 24) + (base_parts[1] << 16) + (base_parts[2] << 8) + base_parts[3]
      
      num_hosts.times do |i|
        ip_int = base_int + i + 1
        ip = "#{(ip_int >> 24) & 255}.#{(ip_int >> 16) & 255}.#{(ip_int >> 8) & 255}.#{ip_int & 255}"
        hosts << ip
      end
    else
      # IP unique
      hosts << network_range
    end
    
    return hosts
  end
  
  def ping_host(host)
    begin
      Timeout.timeout(1) do
        socket = TCPSocket.new(host, 80)
        socket.close
        return true
      end
    rescue
      begin
        Timeout.timeout(1) do
          socket = TCPSocket.new(host, 22)
          socket.close
          return true
        end
      rescue
        return false
      end
    end
  end
  
  def port_scan_host(host, ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 5432, 8080])
    log("Scan des ports pour #{host}")
    
    open_ports = []
    threads = []
    queue = Queue.new
    
    ports.each { |port| queue << port }
    
    5.times do
      threads << Thread.new do
        while port = queue.pop(true) rescue nil
          if scan_port(host, port)
            open_ports << port
            log("Port #{port} ouvert sur #{host}")
          end
        end
      end
    end
    
    threads.each(&:join)
    
    @results[host] = {
      ports: open_ports,
      services: detect_services(host, open_ports),
      timestamp: Time.now.iso8601
    }
    
    return @results[host]
  end
  
  def scan_port(host, port)
    begin
      Timeout.timeout(2) do
        socket = TCPSocket.new(host, port)
        socket.close
        return true
      end
    rescue
      return false
    end
  end
  
  def detect_services(host, ports)
    services = {}
    
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
    
    ports.each do |port|
      services[port] = common_services[port] || 'Unknown'
    end
    
    return services
  end
  
  def generate_scan_report
    log("📊 Génération du rapport de scan")
    
    report = {
      scan_time: Time.now.iso8601,
      interface: @interface,
      targets_found: @targets.length,
      targets: @targets,
      results: @results
    }
    
    report_file = File.join(@output_dir, "network_scan_report.json")
    File.write(report_file, JSON.pretty_generate(report))
    
    log("Rapport de scan généré: #{report_file}")
    return report_file
  end
end

if __FILE__ == $0
  scanner = NetworkScanner.new('eth0', 'results')
  hosts = scanner.scan_network_range('192.168.1.0/24')
  
  hosts.each do |host|
    scanner.port_scan_host(host)
  end
  
  scanner.generate_scan_report
end
