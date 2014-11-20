require 'security_headers/parsers/parser'

module SecurityHeaders
  module Parsers
    class XFrameOptions < Parser
      # X-Frame-Options
      # Syntax:
      # X-Frame-Options = "DENY"
      #                    / "SAMEORIGIN"
      #                    / ( "ALLOW-FROM" RWS SERIALIZED-ORIGIN )
      #
      #          RWS             = 1*( SP / HTAB )
      #                        ; required whitespace
      # Only one can be present
      rule(:x_frame_options) do
        stri("deny") | stri("sameorigin") | allow_from
      end
      root :x_frame_options

      rule(:allow_from) do
        stri("allow-from") >> wsp.repeat(1) >> serialized_origin
      end

      #
      # URI
      #
      rule(:serialized_origin) do
        scheme >> str(":") >> str("//") >> host_name >>
        (str(":") >> digits.as(:port)).maybe
      end
    end
  end
end
