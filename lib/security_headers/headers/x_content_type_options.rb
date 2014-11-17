require 'security_headers/headers/base_parser'

module SecurityHeaders
  class XContentTypeOptions < BaseParser
    module Rules
      def self.included(base)
        # X-Content-Type-Options
        # Syntax:
        # X-Content-Type-Options: nosniff
        base.header_rule("X-Content-Type-Options") do
          stri("nosniff")
        end
      end
    end
    include Rules
  end
end
