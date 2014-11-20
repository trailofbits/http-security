require 'security_headers/parsers/parser'

module SecurityHeaders
  module Parsers
    class XContentTypeOptions < Parser
      # X-Content-Type-Options
      # Syntax:
      # X-Content-Type-Options: nosniff
      rule(:x_content_type_options) { stri("nosniff") }
      root :x_content_type_options
    end
  end
end
