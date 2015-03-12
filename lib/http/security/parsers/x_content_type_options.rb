require 'http/security/parsers/parser'

module HTTP
  module Security
    module Parsers
      class XContentTypeOptions < Parser
        # X-Content-Type-Options
        # Syntax:
        # X-Content-Type-Options: nosniff
        rule(:x_content_type_options) do
          no_sniff.as(:directives)
        end
        root :x_content_type_options

        directive_rule :no_sniff, 'nosniff'
      end
    end
  end
end
