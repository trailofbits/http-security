require 'security_headers/parsers/parser'

module SecurityHeaders
  module Parsers
    class XXSSProtection < Parser
      # X-XSS-Protection
      # Syntax:
      # X-Content-Type-Options: < 1 | 0 >
      #                         /; mode=block
      rule(:x_xss_protection) do
        (str("1") | str("0")) >> (semicolon >> x_xss_mode).maybe
      end
      root :x_xss_protection

      rule(:x_xss_mode) do
        stri("mode") >> equals >> stri("block")
      end
    end
  end
end
