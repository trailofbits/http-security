require 'security_headers/headers/base_parser'

module SecurityHeaders
  class Pragma < BaseParser
    module Rules
      def self.included(base)
        # Pragma
        # Syntax:
        # Pragma            = "Pragma" ":" 1#pragma-directive
        # pragma-directive  = "no-cache" | extension-pragma
        # extension-pragma  = token [ "=" ( token | quoted-string ) ]
       base.header_rule("Pragma") do
          stri("no-cache") | header_extension
        end
      end
    end
    include Rules
  end
end
