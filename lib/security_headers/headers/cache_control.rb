require 'security_headers/parser'

module SecurityHeaders
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
    header_rule("Cache-Control") do
      cache_control_values >> (comma >> cache_control_values).repeat
    end

    rule(:cache_control_values) do
      stri("public")          |
      cc_private              |
      no_cache                |
      stri("no-store")        |
      stri("no-transform")    |
      stri("must-revalidate") |
      max_age                 |
      s_maxage                |
      stri("only-if-cached")  |
      header_extension
    end

  end
end
