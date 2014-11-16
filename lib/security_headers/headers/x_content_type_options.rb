require 'security_headers/parser'

module SecurityHeaders
  class XContentTypeOptions < Parser

    # X-Content-Type-Options
    # Syntax:
    # X-Content-Type-Options: nosniff
    header_rule("X-Content-Type-Options") do
      stri("nosniff")
    end

  end
end
