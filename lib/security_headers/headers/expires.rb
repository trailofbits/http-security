require 'security_headers/parser'

module SecurityHeaders
  class Expires < Parser

    # Expires
    # Syntax:
    # Expires = "Expires" ":" HTTP-date
    # HTTP/1.1 clients and caches MUST treat other invalid date formats,
    # especially including the value "0", as in the past (i.e., "already expired").
    header_rule("Expires") do
      http_date | digits | (str("-") >> digits)
    end

  end
end
