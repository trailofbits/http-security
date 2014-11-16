require 'security_headers/parser'

module SecurityHeaders
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
    # TODO: avoid duplicates (step 2.5)
    header_rule("Content-Security-Policy") do
        csp_pattern
    end

    rule(:csp_pattern) do
        csp_directive >> wsp >> csp_value_sequence >> ( str(";") >> wsp >>
          csp_directive >> wsp >> csp_value_sequence ).repeat(0) >> semicolon.maybe
    end

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

    rule(:csp_value_char) do
      match["\x21-\x2b"] |
      match["#{Regexp.escape("\x2d")}-\x3b"] |
      match["\x3d"]    |
      match["\x3f-\x7e"]
    end


  end
end
