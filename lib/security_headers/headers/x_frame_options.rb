require 'security_headers/headers/base_parser'

module SecurityHeaders
  class XFrameOptions < BaseParser
    module Rules
      def self.included(base)
        # X-Frame-Options
        # Syntax:
        # X-Frame-Options = "DENY"
        #                    / "SAMEORIGIN"
        #                    / ( "ALLOW-FROM" RWS SERIALIZED-ORIGIN )
        #
        #          RWS             = 1*( SP / HTAB )
        #                        ; required whitespace
        # Only one can be present
        base.header_rule("X-Frame-Options") do
          stri("deny") | stri("sameorigin") | allow_from
        end

        base.rule(:allow_from) do
          stri("allow-from") >> wsp.repeat(1) >> serialized_origin
        end

        #
        # URI
        #
        base.rule(:serialized_origin) do
          scheme >> str(":") >> str("//") >> host_name >>
          (str(":") >> digits.as(:port)).maybe
        end
      end
    end
    include Rules
  end
end
