require 'security_headers/parsers/parser'

module SecurityHeaders
  module Parsers
    class XContentTypeOptions < Parser
      # X-Content-Type-Options
      # Syntax:
      # X-Content-Type-Options: nosniff
      rule(:x_content_type_options) do
        nosniff.as(:directives)
      end
      root :x_content_type_options

      rule(:nosniff) do
        stri('nosniff').as(:name)
      end
    end
  end
end
