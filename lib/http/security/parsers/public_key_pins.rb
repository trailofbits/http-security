require 'http/security/parsers/parser'

module HTTP
  module Security
    module Parsers
      class PublicKeyPins < Parser
        rule :public_key_pins do
          (
            public_key_pin_directive >>
            (semicolon >> public_key_pin_directive).repeat(0)
          ).as(:directives)
        end
        root :public_key_pins

        rule(:public_key_pin_directive) do
          pin                |
          unknown_pin        |
          max_age            |
          include_subdomains |
          report_uri         |
          strict             |
          header_extension
        end

        rule(:pin) do
          (stri('pin-') >> hash_algorithm).as(:name) >> equals >>
          quoted_string.as(:value)
        end
        rule(:hash_algorithm) { stri('sha256') }
        rule(:unknown_pin) { stri('pin-') >> token >> equals >> quoted_string }

        directive_rule :include_subdomains, 'includeSubDomains'
        directive_rule :strict

        rule(:report_uri) do
          stri("report-uri").as(:name) >> equals >>
          d_quote >> uri.as(:value) >> d_quote
        end
      end
    end
  end
end
