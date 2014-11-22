require 'http/security/parsers/parser'

module HTTP
  module Security
    module Parsers
      class Expires < Parser
        # Expires
        # Syntax:
        # Expires = "Expires" ":" HTTP-date
        # HTTP/1.1 clients and caches MUST treat other invalid date formats,
        # especially including the value "0", as in the past (i.e., "already expired").
        rule :expires do
          http_date | (str('-').maybe >> digits).as(:numeric)
        end
        root :expires
      end
    end
  end
end
