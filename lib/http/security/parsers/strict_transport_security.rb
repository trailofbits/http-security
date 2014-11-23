require 'http/security/parsers/parser'

module HTTP
  module Security
    module Parsers
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
        rule(:strict_transport_security) do
          (
            (max_age.absent? >> (stp_header_extension >> wsp? >> semicolon >> wsp?)).repeat(0) >>
            max_age >> (semicolon >> stp_header_extension).repeat(0)
          ).as(:directives)
        end
        root :strict_transport_security

        rule(:stp_header_extension) do
          include_subdomains | ( token >> equals >> ( token | quoted_string) )
        end

        rule(:include_subdomains) do
          stri("includeSubDomains").as(:name)
        end
      end
    end
  end
end
