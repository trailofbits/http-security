require 'security_headers/parser'

module SecurityHeaders
  class Pragma < Parser

    # Pragma
    # Syntax:
    # Pragma            = "Pragma" ":" 1#pragma-directive
    # pragma-directive  = "no-cache" | extension-pragma
    # extension-pragma  = token [ "=" ( token | quoted-string ) ]
    header_rule("Pragma") do
      stri("no-cache") | header_extension
    end

  end
end
