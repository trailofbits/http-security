require 'security_headers/parsers/parser'

module SecurityHeaders
  module Parsers
    class Pragma < Parser
      # Pragma
      # Syntax:
      # Pragma            = "Pragma" ":" 1#pragma-directive
      # pragma-directive  = "no-cache" | extension-pragma
      # extension-pragma  = token [ "=" ( token | quoted-string ) ]
      rule(:pragma) do
        stri("no-cache") | header_extension
      end
      root :pragma
    end
  end
end
