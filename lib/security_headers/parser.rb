require "parslet"
module SecurityHeaders
  class Parser < Parslet::Parser
    root :security_headers

    rule(:security_headers) do
      security_header >> (header_sep >> security_header).repeat(0) >> (header_sep | end_header_delimiter).maybe
    end

    rule(:end_header_delimiter) { wsp? >> str("\r\n\r\n") }
    rule(:header_sep) { wsp? >> str("\r\n") >> wsp? }

    rule(:security_header) do
      x_frame_options                   |
      strict_transport_security         |
      x_content_type_options            |
      x_xss_protection                  |
      cache_control                     |
      pragma                            |
      expires                           |
      x_permitted_cross_domain_policies |
      content_security_policy           |
      ignore_nonsecurity_header
    end

    def self.header_to_sym(header)
      header.downcase.gsub("-","_").to_sym
    end

    def self.numeric_match_rule(field_name)
      name = header_to_sym(field_name)
      rule(:"#{name}") do
        stri(field_name) >> equals >> digits                       |
        stri(field_name) >> equals >> s_quote >> digits >> s_quote |
        stri(field_name) >> equals >> d_quote >> digits >> d_quote
      end
    end

    def self.character_match_rule(name, character)
      rule(:"#{name}") do
        wsp? >> str(character) >> wsp?
      end
    end

    def self.header_rule(field_name, &block)
      name = header_to_sym(field_name)
      rule(:"#{name}") do
        wsp? >> stri(field_name) >> wsp? >> str(":") >> wsp? >>
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
    header_rule("X-Frame-Options") do
      stri("deny") | stri("sameorigin") | allow_from
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
    header_rule("Strict-Transport-Security") do
      (include_subdomains >> semicolon >> max_age) |
      (max_age >> (semicolon >> include_subdomains).maybe)
    end

    # X-Content-Type-Options
    # Syntax:
    # X-Content-Type-Options: nosniff
    header_rule("X-Content-Type-Options") do
      stri("nosniff")
    end

    # X-XSS-Protection
    # Syntax:
    # X-Content-Type-Options: < 1 | 0 >
    #                         /; mode=block
    # TODO: support report=<domain>
    header_rule("X-XSS-Protection") do
      (str("1") | str("0")) >> (semicolon >> x_xss_mode).maybe
    end

    # Cache-Control
    # TODO: Parse "field-name" for private/no-cache and support cache-extension
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

    # X-Permitted-Cross-Domain-Policies
    # Syntax:
    # X-Permitted-Cross-Domain-Policies = "none"
    #                    | master-only
    #                    | by-content-type
    #                    | by-ftp-filename
    #                    | all
    header_rule("X-Permitted-Cross-Domain-Policies") do
      stri("none")            |
      stri("master-only")     |
      stri("by-content-type") |
      stri("by-ftp-filename") |
      stri("all")
    end

    # Content-Security-Policy
    # Syntax:
    # Content-Security-Policy =
    # policy-token    = [ directive-token *( ";" [ directive-token ] ) ]
    # directive-token = *WSP [ directive-name [ WSP directive-value ] ]
    # directive-name  = 1*( ALPHA / DIGIT / "-" )
    # directive-value = *( WSP / <VCHAR except ";" and ","> )
    #
    # Parsing Policies:
    # To parse the policy policy, the user agent MUST use an algorithm equivalent to the following:
    #   1. Let the set of directives be the empty set.
    #   2. For each non-empty token returned by strictly splitting the string policy on the character U+003B SEMICOLON (;):
    #     1. Skip whitespace.
    #     2. Collect a sequence of characters that are not space characters. The collected characters are the directive name.
    #     3. If there are characters remaining in token, skip ahead exactly one character (which must be a space character).
    #     4. The remaining characters in token (if any) are the directive value.
    #     5. If the set of directives already contains a directive whose name is a case insensitive match for directive name,
    #        ignore this instance of the directive and continue to the next token.
    #     6. Add a directive to the set of directives with name directive name and value directive value.
    #   3. Return the set of directives.
    # TODO: avoid duplicates (step 2.5)
    header_rule("Content-Security-Policy") do
      csp_directive >> wsp >> csp_value_sequence >> ( str(";") >> wsp >>
        csp_directive >> wsp >> csp_value_sequence ).repeat(0) >> semicolon.maybe
    end

    # Pragma
    # Syntax:
    # Pragma            = "Pragma" ":" 1#pragma-directive
    # pragma-directive  = "no-cache" | extension-pragma
    # extension-pragma  = token [ "=" ( token | quoted-string ) ]
    header_rule("Pragma") do
      stri("no-cache")
    end

    # Expires
    # Syntax:
    # Expires = "Expires" ":" HTTP-date
    #TODO handle integer values
    header_rule("Expires") do
      http_date
    end

    #
    # Directive Helpers
    #
    numeric_match_rule("max-age")
    numeric_match_rule("max-stale")
    numeric_match_rule("min-fresh")
    numeric_match_rule("s-maxage")
    character_match_rule("equals", "=")
    character_match_rule("s_quote", "'")
    character_match_rule("d_quote", '"')
    character_match_rule("semicolon", ";")
    character_match_rule("comma", ",")

    rule(:cache_control_values) do
      stri("public")          |
      stri("private")         |
      stri("no-cache")        |
      stri("no-store")        |
      stri("no-transform")    |
      stri("must-revalidate") |
      max_age                 |
      s_maxage                |
      stri("only-if-cached")
    end

    rule(:allow_from) do
      stri("allow-from") >> wsp.repeat(1) >> serialized_origin
    end

    rule(:include_subdomains) do
      stri("includeSubDomains")
    end

    rule(:x_xss_mode) do
      stri("mode") >> equals >> stri("block")
    end

    # HTTP-date    = rfc1123-date | rfc850-date | asctime-date
    # rfc1123-date = wkday "," SP date1 SP time SP "GMT"
    # rfc850-date  = weekday "," SP date2 SP time SP "GMT"
    # asctime-date = wkday SP date3 SP time SP 4DIGIT
    # date1        = 2DIGIT SP month SP 4DIGIT
    #               ; day month year (e.g., 02 Jun 1982)
    # date2        = 2DIGIT "-" month "-" 2DIGIT
    #               ; day-month-year (e.g., 02-Jun-82)
    # date3        = month SP ( 2DIGIT | ( SP 1DIGIT ))
    #               ; month day (e.g., Jun  2)
    # time         = 2DIGIT ":" 2DIGIT ":" 2DIGIT
    #               ; 00:00:00 - 23:59:59
    # wkday        = "Mon" | "Tue" | "Wed"
    #             | "Thu" | "Fri" | "Sat" | "Sun"
    # weekday      = "Monday" | "Tuesday" | "Wednesday"
    #             | "Thursday" | "Friday" | "Saturday" | "Sunday"
    # month        = "Jan" | "Feb" | "Mar" | "Apr"
    #             | "May" | "Jun" | "Jul" | "Aug"
    #             | "Sep" | "Oct" | "Nov" | "Dec"
    rule(:http_date) do
      rfc1123_date |
      rfc850_date  |
      asctime_date
    end

    rule(:rfc1123_date) do
      wkday >> str(",") >> wsp >> date1 >> wsp >> time >> wsp >> str("GMT")
    end

    rule(:rfc850_date) do
      weekday >> str(",") >> wsp >> date2 >> wsp >> time >> wsp >> str("GMT")
    end

    rule(:asctime_date) do
      wkday >> wsp >> date3 >> wsp >> time >> wsp >> four_digit
    end

    #day month year (e.g., 02 Jun 1982)
    rule(:date1) do
      two_digit >> wsp >> month >> wsp >> four_digit
    end

    #day-month-year (e.g., 02-Jun-82)
    rule(:date2) do
      two_digit >> str("-") >> month >> str("-") >> two_digit
    end

    #month day (e.g., Jun  2)
    rule(:date3) do
      month >> wsp >> (two_digit | (wsp >> one_digit))
    end

    #00:00:00 - 23:59:59
    rule(:time) do
      two_digit >> str(":") >> two_digit >> str(":") >> two_digit
    end

    rule(:four_digit) do
      digit.repeat(4,4)
    end

    rule(:two_digit) do
      digit.repeat(2,2)
    end

    rule(:one_digit) do
      digit.repeat(1,1)
    end

    rule(:ignore_nonsecurity_header) do
      (header_sep.absent? >> any).repeat(1)
    end

    rule(:wkday) do
      stri("Mon") |
      stri("Tue") |
      stri("Wed") |
      stri("Thu") |
      stri("Fri") |
      stri("Sat") |
      stri("Sun")
    end

    rule(:weekday) do
      stri("Monday")    |
      stri("Tuesday")   |
      stri("Wednesday") |
      stri("Thursday")  |
      stri("Friday")    |
      stri("Saturday")  |
      stri("Sunday")
    end

    rule(:month) do
      stri("Jan") |
      stri("Feb") |
      stri("Mar") |
      stri("Apr") |
      stri("May") |
      stri("Jun") |
      stri("Jul") |
      stri("Aug") |
      stri("Sep") |
      stri("Oct") |
      stri("Nov") |
      stri("Dec")
    end

    #
    # URI
    #
    rule(:serialized_origin) do
      scheme >> str(":") >> str("//") >> host_name >>
      (str(":") >> digits.as(:port)).maybe
    end

    rule(:uri) {
      scheme.as(:scheme) >> str(":") >> str("//").maybe >>
      (user_info.as(:user_info) >> str("@")).maybe >>
      host_name.as(:host) >>
      (str(":") >> digits.as(:port)).maybe >>
      uri_path
    }

    #
    # Character Classes
    #
    rule(:digit) { match["0-9"] }
    rule(:digits) { digit.repeat(1) }
    rule(:xdigit) { digit | match["a-fA-F"] }
    rule(:upper) { match["A-Z"] }
    rule(:lower) { match["a-z"] }
    rule(:alpha) { upper | lower }
    rule(:alnum) { alpha | digit }
    rule(:cntrl) { match["\x00-\x1f"] }
    rule(:ascii) { match["\x00-\x7f"] }
    rule(:lws) { match[" \t"] }
    rule(:crlf) { str("\r\n") }
    rule(:alphanum) { alpha | digit }
    rule(:wsp) { str(" ") | str("\t") }
    rule(:lws) { match[" \t"] }
    rule(:wsp?) { lws.repeat }

    #
    # CSP Helpers
    #
    rule(:csp_value_sequence) { csp_value >> (wsp >> csp_value).repeat(0) }

    rule(:csp_directive) { csp_directive_char.repeat }
    rule(:csp_value) { csp_value_char.repeat }

    #CSP tokens are any character except space, comma and semicolon
    rule(:csp_directive_char) do
      alpha | digit | str("-")
    end

    #TODO blacklist bad chars instead of whitelist valid chars
    rule(:csp_value_char) do
      match["\x00-\x1f"] |
      match["\x21-\x2b"] |
      match["\x2d-\x3a"] |
      match["\x3c-\x7f"]
    end

    #
    # URI Elements
    #
    rule(:scheme) do
      ( alpha | digit | match("[+-.]") ).repeat
    end

    rule(:host_name) do
      ( alnum | match("[-_.]") ).repeat(1)
    end

    #
    # Misc
    #
    rule(:unknown_header) { match["^=; \t"].repeat(1) }

    def stri(str)
      key_chars = str.split(//)
      key_chars.
        collect! { |char| match["#{char.upcase}#{char.downcase}"] }.
        reduce(:>>)
    end
  end
end
