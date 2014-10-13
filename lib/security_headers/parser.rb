require 'parslet'
module SecurityHeaders
  class Parser < Parslet::Parser
    root :security_headers

    rule(:security_headers) do
      (security_header).repeat >>
      header_sep.maybe #>> end_header_delimiter.maybe
    end

    rule(:header_sep) { wsp? >> str('\r\n') >> wsp? }

    rule(:security_header) do
      x_frame_options           |
      strict_transport_security |
      x_content_type_options    |
      x_xss_protection          |
      cache_control
    end

    def self.header_to_sym(header)
      header.downcase.gsub("-","_").to_sym
    end
    private_class_method :header_to_sym

    # @param [String] field_name
    #  Formatted header field-name
    #
    # @param [block] block
    #  Parslet block for evaluating header content
    #
    # @return  [Hash{Symbol => Object}]
    #   The formatted Hash of header field-name/field-content pair
    #
    def self.header_rule(field_name, &block)
      name = header_to_sym(field_name)
      rule(:"#{name}") do
        wsp? >> str(field_name) >> wsp? >> str(':') >> wsp? >>
        (instance_eval(&block).as(name) | unknown_header) >> wsp?
      end
    end

    # X-Frame-Options
    # Syntax:
    # X-Frame-Options = "DENY"
    #                    / "SAMEORIGIN"
    #                    / ( "ALLOW-FROM" RWS SERIALIZED-ORIGIN )
    #
    #          RWS             = 1*( SP / HTAB )
    #                        ; required whitespace
    # Only one can be present
    header_rule('X-Frame-Options') do
      str('deny') | str('sameorigin') | allow_from
    end

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
    #
    header_rule('Strict-Transport-Security') do
      (include_subdomains >> semicolon_sep >> max_age) |
      (max_age >> (semicolon_sep >> include_subdomains).maybe)
    end

    # X-Content-Type-Options
    # Syntax:
    # X-Content-Type-Options: nosniff
    header_rule('X-Content-Type-Options') do
      str("nosniff")
    end

    # X-XSS-Protection
    # Syntax:
    # X-Content-Type-Options: < 1 | 0 >
    #                         /; mode=block
    # TODO: support report=<domain>
    header_rule('X-XSS-Protection') do
      (str("1") | str("0")) >> (semicolon_sep >> x_xss_mode).maybe
    end

    # Cache-Control
    # Syntax:
    #
    # Cache-Control   = "Cache-Control" ":" 1#cache-directive
    # cache-directive = cache-request-directive
    #      | cache-response-directive
    # cache-request-directive =
    #        "no-cache"                          ; Section 14.9.1
    #      | "no-store"                          ; Section 14.9.2
    #      | "max-age" "=" delta-seconds         ; Section 14.9.3, 14.9.4
    #      | "max-stale" [ "=" delta-seconds ]   ; Section 14.9.3
    #      | "min-fresh" "=" delta-seconds       ; Section 14.9.3
    #      | "no-transform"                      ; Section 14.9.5
    #      | "only-if-cached"                    ; Section 14.9.4
    #      | cache-extension                     ; Section 14.9.6
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
    header_rule('Cache-Control') do
      #TODO
    end



    #
    # Directive Helpers
    #
    rule(:allow_from) do
      str('allow-from') >> wsp.repeat(1) >> serialized_origin
    end

    rule(:semicolon_sep) { wsp? >> str(';') >> wsp? }

    rule(:max_age) do
      str('max-age') >> equals >> digits                       |
      str('max-age') >> equals >> s_quote >> digits >> s_quote |
      str('max-age') >> equals >> d_quote >> digits >> d_quote
    end

    rule(:include_subdomains) do
      str("includeSubDomains")
    end

    rule(:x_xss_mode) do
      str("mode") >> equals >> str("block")
    end

    rule(:equals) do
      wsp? >> str("=") >> wsp?
    end

    rule(:s_quote) do
      wsp? >> str('"') >> wsp?
    end

    rule(:d_quote) do
      wsp? >> str("'") >> wsp?
    end

    #
    # URI
    #
    rule(:serialized_origin) do
      scheme >> str(':') >> str('//') >> host_name >>
      (str(':') >> digits.as(:port)).maybe
    end

    rule(:uri) {
      scheme.as(:scheme) >> str(':') >> str('//').maybe >>
      (user_info.as(:user_info) >> str('@')).maybe >>
      host_name.as(:host) >>
      (str(':') >> digits.as(:port)).maybe >>
      uri_path
    }

    #
    # Character Classes
    #
    rule(:digit) { match['0-9'] }
    rule(:digits) { digit.repeat(1) }
    rule(:xdigit) { digit | match['a-fA-F'] }
    rule(:upper) { match['A-Z'] }
    rule(:lower) { match['a-z'] }
    rule(:alpha) { upper | lower }
    rule(:alnum) { alpha | digit }
    rule(:cntrl) { match['\x00-\x1f'] }
    rule(:ascii) { match['\x00-\x7f'] }
    rule(:lws) { match[" \t"] }
    rule(:crlf) { str("\r\n") }
    rule(:alphanum) { alpha | digit }
    rule(:wsp) { str(' ') | str("\t") }
    rule(:lws) { match[" \t"] }
    rule(:wsp?) { lws.repeat }


    #
    # URI Elements
    #
    rule(:scheme) do
      ( alpha | digit | match('[+-.]') ).repeat
    end

    rule(:host_name) do
      ( alnum | match('[-_.]') ).repeat(1)
    end

    #
    # Misc
    #
    rule(:unknown_header) { match["^=; \t"].repeat(1) }
    rule(:end_header_delimiter) { str.match("\r\n\r\n") }

  end
end
