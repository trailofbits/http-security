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
        cache_control_values >> (comma >> cache_control_values).repeat
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

      def self.directive_rule(name,string=nil)
        string ||= name.to_s.tr('_','-')

        rule(name) { stri(string).as(name) }
      end

      directive_rule :cc_public, 'public'

      #"private" [ "=" <"> 1#field-name <"> ];
      rule(:cc_private) do
        (
          stri("private") >> ( equals >> field_name.as(:field) ).maybe
        ).as(:private)
      end

      #"no-cache" [ "=" <"> 1#field-name <"> ];
      rule(:no_cache) do
        (
          stri("no-cache") >> ( equals >> field_name ).maybe
        ).as(:no_cache)
      end

      directive_rule :no_store
      directive_rule :no_transform
      directive_rule :must_revalidate
      directive_rule :only_if_cached
    end
  end
end
