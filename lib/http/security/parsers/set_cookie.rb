require 'http/security/parsers/parser'

module HTTP
  module Security
    module Parsers
      class SetCookie < Parser

        root :set_cookie
        rule(:set_cookie) do
          cookie_pair.as(:cookie) >> (str('; ') >> cookie_av).repeat(0)
        end

        rule(:cookie_pair) do
          cookie_name.as(:name) >> str('=') >> cookie_value.as(:value)
        end

        rule(:cookie_name) { token }

        rule(:cookie_value) do
          cookie_octet.repeat(0) |
          str('"') >> cookie_octet.repeat(0) >> str('"')
        end

        # US-ASCII characters excluding CTLs,
        # whitespace DQUOTE, comma, semicolon,
        # and backslash
        rule(:cookie_octet) do
          match['\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e']
        end

        rule(:cookie_av) do
          expires_av | max_age_av | domain_av | path_av | secure_av | httponly_av | extension_av
        end

        rule(:expires_av) { stri('Expires=') >> sane_cookie_date.as(:expires) }
        rule(:sane_cookie_date) { rfc1123_date }
        rule(:max_age_av) do
          stri('Max-Age=') >> (non_zero_digit >> digit.repeat(0)).as(:max_age)
        end

        rule(:non_zero_digit) { match['\x31-\x39'] } # 1-9
        rule(:domain_av) { stri('Domain=') >> domain_value.as(:domain) }
        rule(:domain_value) { host_name }

        rule(:path_av) { stri('Path=') >> path_value.as(:path) }
        # <any CHAR except CTLs or ";">
        rule(:path_value) { match['^\x00-\x1f\x7f;'].repeat(0) }
        rule(:secure_av) { stri('Secure').as(:secure) }
        rule(:httponly_av) { stri('HttpOnly').as(:http_only) }
        # <any CHAR except CTLs or ";">
        rule(:extension_av) { match['^\x00-\x1f\x7f;'] }

      end
    end
  end
end
