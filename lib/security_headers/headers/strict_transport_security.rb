require 'security_headers/parser'

module SecurityHeaders
  class StrictTransportSecurity < Parser

    # Strict-Transport-Security
    # Syntax:
    #  Strict-Transport-Security = "Strict-Transport-Security" ":"
    #                              [ directive ]  *( ";" [ directive ] )
    #
    #  directive                 = directive-name [ "=" directive-value ]
    #  directive-name            = token
    #  directive-value           = token | quoted-string
    #
    # where:
    #
    # token          = <token, defined in [RFC2616], Section 2.2>
    # quoted-string  = <quoted-string, defined in [RFC2616], Section 2.2>
    #
    # REQUIRED directives: max-age
    # OPTIONAL directives: includeSubdomains
    header_rule("Strict-Transport-Security") do
        (max_age.absent? >> (stp_header_extension >> wsp? >> semicolon >> wsp?)).repeat(0) >>
          max_age >> ( wsp? >> semicolon >> wsp? >> stp_header_extension).repeat(0)
    end

    rule(:stp_header_extension) { include_subdomains | ( extension_token >> equals >> ( extension_token | quoted_string) ) }

  end
end
