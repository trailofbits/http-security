require 'http/security/parsers/parser'

module HTTP
  module Security
    module Parsers
      class Pragma < Parser
        # Pragma
        # Syntax:
        # Pragma            = "Pragma" ":" 1#pragma-directive
        # pragma-directive  = "no-cache" | extension-pragma
        # extension-pragma  = token [ "=" ( token | quoted-string ) ]
        rule(:pragma) do
          (
            no_cache | header_extension
          ).as(:directives)
        end
        root :pragma

        rule(:no_cache) do
          stri('no-cache').as(:key)
        end
      end
    end
  end
end
