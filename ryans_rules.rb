require './ruby_ids'
require './http_parser'
require './file_logger'
require 'pcaplet'

class RyansRules < RubyIDS

  puts "Loading"

  alert 'Testing' do
    puts packet.to_s
  end

  alert 'ET TROJAN Zeus CnC Checkin POST to Config.php' do
    is_http? &&
    http_packet.http_method == "POST" &&
    http_packet.uri =~ /\/config.php/ &&
    http_packet['accept'] == "*/*" &&
    http_packet['content-type'] == "application/x-www-form-urlencoded" &&
    http_packet['user-agent'] =~ /Mozilla\/4.0 \(compatible; MSIE 8.0; Windows NT 5.1;/
  end

  alert 'Google in URI' do
    is_http? &&
    http_packet.uri =~ /google/i
  end

end

RyansRules.begin_listening