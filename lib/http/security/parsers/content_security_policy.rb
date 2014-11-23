require 'http/security/parsers/parser'

module HTTP
  module Security
    module Parsers
      class ContentSecurityPolicy < Parser
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
        rule(:csp_pattern) do
          csp_directive >> wsp >> source_list >> (
            str(";") >> wsp >>
            csp_directive >> wsp >> source_list
          ).repeat(0) >> semicolon.maybe
        end
        root :csp_pattern

        rule(:csp_entry) do
          (csp_directive >> wsp >> source_list) |
          report_uri                            |
          sandbox
        end

        rule(:csp_directive) do
          stri("default-src") |
          stri("script-src")  |
          stri("object-src")  |
          stri("style-src")   |
          stri("img-src")     |
          stri("media-src")   |
          stri("frame-src")   |
          stri("font-src")    |
          stri("connect-src") |
          stri("sandbox")     |
          stri("report-uri")
        end

        # Source list
        # Syntax:
        # source-list       = *WSP [ source-expression *( 1*WSP source-expression ) *WSP ]
        #                   / *WSP "'none'" *WSP
        # source-expression = scheme-source / host-source / keyword-source
        # scheme-source     = scheme ":"
        # host-source       = [ scheme "://" ] host [ port ]
        # ext-host-source   = host-source "/" *( <VCHAR except ";" and ","> )
        #                   ; ext-host-source is reserved for future use.
        # keyword-source    = "'self'" / "'unsafe-inline'" / "'unsafe-eval'"
        # scheme            = <scheme production from RFC 3986>
        # host              = "*" / [ "*." ] 1*host-char *( "." 1*host-char )
        # host-char         = ALPHA / DIGIT / "-"
        # port              = ":" ( 1*DIGIT / "*" )
        rule(:source_list) do
          (wsp? >> stri("'none'") >> wsp?) |
          (wsp? >> source_expression >> (wsp >> source_expression).repeat(0))
        end

        rule(:source_expression) do
          scheme_source | host_source | keyword_source
        end

        rule(:csp_vchar) do
          match["\x20-\x2b"]                     |
          match["#{Regexp.escape("\x2d")}-\x3a"] |
          match["\x3c-\x7f"]
        end

        rule(:scheme_source) do
          (scheme >> str("://")).absent? >> scheme >> str(":")
        end

        rule(:host_source) do
          (scheme >> str("://")).maybe >> csp_host >> port.maybe
        end

        rule(:csp_host) do
          (str("*.").maybe >> host_char.repeat(1) >> ( str(".") >> host_char.repeat(1) ).repeat(0)) |
          str("*")
        end

        rule (:host_char) do
          alnum | str("-")
        end

        rule(:keyword_source) do
          stri("'self'") | stri("'unsafe-inline'") | stri("'unsafe-eval'")
        end

        rule(:port) do
          str(":") >> digits.as(:port)
        end

        rule(:ext_host_source) do
          (scheme >> str("://")).maybe >> csp_host >> ext_host_source.maybe >> port.maybe
        end

        # report-uri
        # directive-name    = "report-uri"
        # directive-value   = uri-reference *( 1*WSP uri-reference )
        # uri-reference     = <URI-reference from RFC 3986>
        rule(:report_uri) do
          stri("report-uri") >> uri >> uri.repeat(0)
        end

        # sandbox (Optional)
        # directive-name    = "sandbox"
        # directive-value   = token *( 1*WSP token )
        # token             = <token from RFC 2616>
        rule(:sandbox) do
          stri("sandbox") >> token >> token.repeat(0)
        end
      end
    end
  end
end
