require 'security_headers/headers/base_parser'

module SecurityHeaders
  class XXSSProtection < BaseParser
    module Rules
      def self.included(base)
        # X-XSS-Protection
        # Syntax:
        # X-Content-Type-Options: < 1 | 0 >
        #                         /; mode=block
        base.header_rule("X-XSS-Protection") do
          (str("1") | str("0")) >> (semicolon >> x_xss_mode).maybe
        end
      end
    end
    include Rules
  end
end
