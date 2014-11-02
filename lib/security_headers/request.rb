require 'security_headers/parser'
require 'curb'

module SecurityHeaders
  class Request
    def self.parse_headers(domain)
      begin
        head = Curl::Easy.http_head(domain)
        Parser.new.parse(head.header_str)
      rescue => error
        puts error
      end
    end
  end
end
