require 'pcaplet'

class String
  def starts_with?(prefix)
    prefix = prefix.to_s
    self[0, prefix.length] == prefix
  end
end

class RubyIDS

  class << self

    def set_variable(name, value)
      @variables || initialize_variables
      @variables[name] = value
    end

    def initialize_variables
      @variables = {}
      @variables['http_ports'] = [80, 8080]
    end

    def variables
      @variables
    end

    def alert(title, &block)
      @rules ||= {}
      @rules[title] = block
    end

    def parse_packet(packet)
      if !@ready_to_listen
        puts "Not ready to listen!"
        return
      end
      @packet = packet
      return if packet.nil?
      @rules.each do |name, block|
        begin
        if block.call
          log(name, packet)
        end
        rescue
          puts "Parsing for rule #{name} failed"
          puts $!
        end
      end
    end

    def packet
      @packet
    end

    def begin_listening
      @rules ||= {}
      @variables || initialize_variables
      @ready_to_listen = true
      httpdump = Pcaplet.new('-s 1500')
      httpdump.each_packet {|pkt|
        parse_packet(pkt)
      }
    end

    def source_port
      @packet.sport if @packet && (@packet.tcp? || @packet.udp?)
    end

    def dest_port
      @packet.dport if @packet && (@packet.tcp? || @packet.udp?)
    end

    def log(alert, packet)
      puts "#{Time.now.to_s} - #{packet.src} -> #{packet.dst} #{alert}"
      puts packet.tcp_data
      puts "\n\n"
    end

  end


end

