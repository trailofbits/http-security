require 'security_headers/headers/base_parser'

module SecurityHeaders
  class Expires < BaseParser
    module Rules
      def self.included(base)
        # Expires
        # Syntax:
        # Expires = "Expires" ":" HTTP-date
        # HTTP/1.1 clients and caches MUST treat other invalid date formats,
        # especially including the value "0", as in the past (i.e., "already expired").
        base.header_rule("Expires") do
          http_date | digits | (str("-") >> digits)
        end
      end
    end
    include Rules
  end
end
