#File logger - Provides output to file for logs

class RubyIDS

  class << self

    alias :old_log :log

    def log(alert, packet)
      log_file = @variables['log_file'] || "ruby_ids.log"
      packet_data = packet.tcp_data if packet.tcp?
      packet_data = packet.udp_data if packet.udp?
      packet_data = "" if packet_data.nil?
      File.open(log_file, 'a+') {|f| f.write("#{Time.now.to_s} - #{packet.src} -> #{packet.dst} #{alert}\n#{packet_data}") }
      self.send(:old_log, alert, packet)
      puts "#{Time.now.to_s} - #{packet.src} -> #{packet.dst} #{alert}\n#{packet_data}"
    end

  end

end