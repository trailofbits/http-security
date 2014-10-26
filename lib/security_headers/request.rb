require 'security_headers/parser'
require 'net/http'
require 'tempfile'

module SecurityHeaders
  class Request

    def self.head(domain)
      begin
        head = Curl::Easy.http_head("http://www.google.com")
        new(Parser.new.parse(h.header_str))
      rescue => error
        puts error
      end
    end

  end
end
