#HTTP Parser - Extends Ruby IDS to provide HTTP Processing for rules

class RubyIDS
  class << self

    def http_packet
      return nil if !is_http?
      return HTTPPacket.new(@packet)
    end

    def is_http?
      @packet &&
      @packet.tcp? &&
      @packet.tcp_data &&
      @packet.tcp_data.length > 3 &&
      (@variables['http_ports'].include?(@packet.sport) || @variables['http_ports'].include?(@packet.dport))
    end

    def is_http_request?
      is_http? && @variables['http_ports'].include?(@packet.dport)
    end

    def is_http_response?
      is_http? && @variables['http_ports'].include?(@packet.sport)
    end
  end

end

class HTTPPacket

  def initialize(packet)
    return nil if packet.nil? || packet.tcp_data.nil? || packet.tcp_data == ''
    #puts packet.tcp_data.to_s
    @packet = packet
    @lines = @packet.tcp_data.split(/\r\n/)
  end

  def uri
    return '' if @packet.nil? || @packet.tcp_data.nil? || @packet.tcp_data.starts_with?('HTTP')
    return '' if @lines.nil?
    groups = @lines[0].match(/[^ ]* ([^ ]*) /)
    groups[1] if groups
  end

  def http_method
    return nil if @lines.nil? || @lines[0].nil?
    @lines[0].split(' ')[0]
  end

  def [](method_name)
    return '' if @lines.nil?
    @lines.each do |line|
      if line.downcase.starts_with? method_name.downcase
        #puts line
        regex = Regexp.new("#{method_name.downcase}: (.*)$", true)
        groups = line.match(regex)
        #puts groups.inspect unless groups.nil?
        #puts groups[1] unless groups.nil?
        return groups[1] unless groups.nil? || groups[1].nil?
      end
    end
  end

  def to_s
    return '' if @packet.nil? || @packet.tcp_data.nil?
    to_return = ''
    begin
      to_return = Zlib::GzipReader.new(StringIO.new(@packet.tcp_data.to_s))
    rescue
      to_return = @packet.tcp_data.to_s
    end
    to_return
    #@packet.tcp_data.to_s
  end

end