require 'security_headers/parser'

module SecurityHeaders
  class XXSSProtection < Parser

    # X-XSS-Protection
    # Syntax:
    # X-Content-Type-Options: < 1 | 0 >
    #                         /; mode=block
    header_rule("X-XSS-Protection") do
      (str("1") | str("0")) >> (semicolon >> x_xss_mode).maybe
    end

  end
end
