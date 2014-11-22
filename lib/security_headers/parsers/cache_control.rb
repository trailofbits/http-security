require 'security_headers/parsers/parser'

module SecurityHeaders
  module Parsers
    class CacheControl < Parser
      # Cache-Control
      # Syntax:
      # Cache-Control   = "Cache-Control" ":" 1#cache-directive
      # cache-directive = cache-response-directive
      #  cache-response-directive =
      #        "public"                               ; Section 14.9.1
      #      | "private" [ "=" <"> 1#field-name <"> ] ; Section 14.9.1
      #      | "no-cache" [ "=" <"> 1#field-name <"> ]; Section 14.9.1
      #      | "no-store"                             ; Section 14.9.2
      #      | "no-transform"                         ; Section 14.9.5
      #      | "must-revalidate"                      ; Section 14.9.4
      #      | "proxy-revalidate"                     ; Section 14.9.4
      #      | "max-age" "=" delta-seconds            ; Section 14.9.3
      #      | "s-maxage" "=" delta-seconds           ; Section 14.9.3
      #      | cache-extension                        ; Section 14.9.6
      # cache-extension = token [ "=" ( token | quoted-string ) ]
      rule(:cache_control) do
        (
          cache_control_values >> (comma >> cache_control_values).repeat
        ).as(:directives)
      end
      root :cache_control

      rule(:cache_control_values) do
        cc_public       |
        cc_private      |
        no_cache        |
        no_store        |
        no_transform    |
        must_revalidate |
        max_age         |
        s_maxage        |
        only_if_cached  |
        header_extension
      end

      #"private" [ "=" <"> 1#field-name <"> ];
      rule(:cc_public) do
        stri("public").as(:name) >> (equals >> field_name.as(:value)).maybe
      end

      #"private" [ "=" <"> 1#field-name <"> ];
      rule(:cc_private) do
        stri("private").as(:name) >> (equals >> field_name.as(:value)).maybe
      end

      field_directive_rule :no_cache, 'no-cache'
      directive_rule :no_store, 'no-store'
      directive_rule :no_transform, 'no-transform'
      directive_rule :must_revalidate, 'must-revalidate'
      directive_rule :only_if_cached, 'only-if-cached'

    end
  end
end
