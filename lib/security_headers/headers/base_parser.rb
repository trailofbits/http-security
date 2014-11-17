require "parslet"

module SecurityHeaders
  class BaseParser < Parslet::Parser

    module Rules
      def self.included(base)
        base.send :extend, ClassMethods

        #
        # Directive Helpers
        #
        base.numeric_match_rule("max-age")
        base.numeric_match_rule("max-stale")
        base.numeric_match_rule("min-fresh")
        base.numeric_match_rule("s-maxage")
        base.character_match_rule("equals", "=")
        base.character_match_rule("s_quote", "'")
        base.character_match_rule("d_quote", '"')
        base.character_match_rule("semicolon", ";")
        base.character_match_rule("comma", ",")


        base.rule(:include_subdomains) do
          stri("includeSubDomains")
        end

        base.rule(:x_xss_mode) do
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
        base.rule(:http_date) do
          rfc1123_date |
          rfc850_date  |
          asctime_date
        end

        base.rule(:rfc1123_date) do
          wkday >> str(",") >> wsp >> date1 >> wsp >> time >> wsp >> str("GMT")
        end

        base.rule(:rfc850_date) do
          weekday >> str(",") >> wsp >> date2 >> wsp >> time >> wsp >> str("GMT")
        end

        base.rule(:asctime_date) do
          wkday >> wsp >> date3 >> wsp >> time >> wsp >> four_digit
        end

        #day month year (e.g., 02 Jun 1982)
        base.rule(:date1) do
          two_digit >> wsp >> month >> wsp >> four_digit
        end

        #day-month-year (e.g., 02-Jun-82)
        base.rule(:date2) do
          two_digit >> str("-") >> month >> str("-") >> two_digit
        end

        #month day (e.g., Jun  2)
        base.rule(:date3) do
          month >> wsp >> (two_digit | (wsp >> one_digit))
        end

        #00:00:00 - 23:59:59
        base.rule(:time) do
          two_digit >> str(":") >> two_digit >> str(":") >> two_digit
        end

        base.rule(:four_digit) do
          digit.repeat(4,4)
        end

        base.rule(:two_digit) do
          digit.repeat(2,2)
        end

        base.rule(:one_digit) do
          digit.repeat(1,1)
        end

        base.rule(:wkday) do
          stri("Mon") |
          stri("Tue") |
          stri("Wed") |
          stri("Thu") |
          stri("Fri") |
          stri("Sat") |
          stri("Sun")
        end

        base.rule(:weekday) do
          stri("Monday")    |
          stri("Tuesday")   |
          stri("Wednesday") |
          stri("Thursday")  |
          stri("Friday")    |
          stri("Saturday")  |
          stri("Sunday")
        end

        base.rule(:month) do
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


        base.rule(:uri) {
          scheme.as(:scheme) >> str(":") >> str("//").maybe >>
          (user_info.as(:user_info) >> str("@")).maybe >>
          host_name.as(:host) >>
          (str(":") >> digits.as(:port)).maybe >>
          uri_path
        }

        #
        # Character Classes
        #
        base.rule(:digit) { match["0-9"] }
        base.rule(:digits) { digit.repeat(1) }
        base.rule(:xdigit) { digit | match["a-fA-F"] }
        base.rule(:upper) { match["A-Z"] }
        base.rule(:lower) { match["a-z"] }
        base.rule(:alpha) { upper | lower }
        base.rule(:alnum) { alpha | digit }
        base.rule(:cntrl) { match["\x00-\x1f"] }
        base.rule(:ascii) { match["\x00-\x7f"] }
        base.rule(:alphanum) { alpha | digit }
        base.rule(:wsp) { match[" \t"] }
        base.rule(:wsp?) { wsp.repeat }

        #
        # Cache Control Helpers
        # quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
        # qdtext         = OWS / %x21 / %x23-5B / %x5D-7E / obs-text
        # obs-text       = %x80-FF
        # quoted-pair    = "\" ( WSP / VCHAR / obs-text )
        #
        base.rule(:header_extension) { ( extension_token >> equals >> ( extension_token | quoted_string) ) }
        base.rule(:extension_token) { extension_token_char.repeat }

        base.rule(:quoted_string) do
          d_quote >> quoted_string_text >> d_quote
        end

        base.rule(:quoted_string_text) do
          qdtext | quoted_pair
        end

        base.rule(:qdtext) do
          ( wsp | match["\x21"] | match["\x23-\x5B"] | match["\x5D-\x7E"] | obs_text).repeat(1)
        end

        base.rule(:quoted_pair) do
          (wsp | obs_text | vchar).repeat(1)
        end

        base.rule(:vchar) do
          match["\x20-\x7f"]
        end

        base.rule(:obs_text) do
          match["\x80-\xFF"]
        end

        #"no-cache" [ "=" <"> 1#field-name <"> ];
        base.rule(:no_cache) do
          stri("no-cache") >> ( equals >> field_name ).maybe
        end

        #"private" [ "=" <"> 1#field-name <"> ];
        base.rule(:cc_private) do
          stri("private") >> ( equals >> field_name ).maybe
        end

        base.rule(:field_name) do
          valid_field_name | ( d_quote >> valid_field_name >> d_quote )
        end

        base.rule(:valid_field_name) do
          stri("Access-Control-Allow-Origin")   |
          stri("Accept-Ranges")             |
          stri("Age")                       |
          stri("Allow")                     |
          stri("Cache-Control")             |
          stri("Connection")                |
          stri("Content-Encoding")          |
          stri("Content-Language")          |
          stri("Content-Length")            |
          stri("Content-Location")          |
          stri("Content-MD5")               |
          stri("Content-Disposition")       |
          stri("Content-Range")             |
          stri("Content-Type")              |
          stri("ETag")                      |
          stri("Expires")                   |
          stri("Last-Modified")             |
          stri("Link")                      |
          stri("Location")                  |
          stri("P3P")                       |
          stri("Pragma")                    |
          stri("Proxy-Authenticate")        |
          stri("Refresh")                   |
          stri("Retry-After")               |
          stri("Server")                    |
          stri("Set-Cookie")                |
          stri("Status")                    |
          stri("Strict-Transport-Security") |
          stri("Trailer")                   |
          stri("Transfer-Encoding")         |
          stri("Upgrade")                   |
          stri("Vary")                      |
          stri("Via")                       |
          stri("Warning")                   |
          stri("WWW-Authenticate")          |
          stri("X-Frame-Options")
        end


        #1*<any (US-ASCII) CHAR except SPACE, CTLs, or tspecials>
        base.rule(:extension_token_char) do
          match["\x21"]      |
          match["\x23-\x27"] |
          match["\x2a-\x2b"] |
          match["#{Regexp.escape("\x2d")}-\x2e"] |
          match["\x30-\x39"] |
          match["\x41-\x5a"] |
          match["\x5f-\x7a"] |
          match["\x7c"]      |
          match["\x7e"]
        end

        #
        # URI Elements
        #
        base.rule(:scheme) do
          ( alpha | digit | match("[+-.]") ).repeat
        end

        base.rule(:host_name) do
          ( alnum | match("[-_.]") ).repeat(1)
        end

        #
        # Misc
        #
        base.rule(:unknown_header) { match["^=; \t"].repeat(1) }
      end

      module ClassMethods
        def header_to_sym(header)
          header.downcase.gsub("-","_").to_sym
        end

        def numeric_match_rule(field_name)
          name = header_to_sym(field_name)
          rule(:"#{name}") do
            stri(field_name) >> equals >> digits                       |
            stri(field_name) >> equals >> s_quote >> digits >> s_quote |
            stri(field_name) >> equals >> d_quote >> digits >> d_quote
          end
        end

        def character_match_rule(name, character)
          rule(:"#{name}") do
            wsp? >> str(character) >> wsp?
          end
        end

        def header_rule(field_name, &block)
          name = header_to_sym(field_name)
          rule(:"#{name}") do
            wsp? >> stri(field_name) >> wsp? >> str(":") >> wsp? >>
            (instance_eval(&block).as(name) | unknown_header) >> wsp?
          end
        end
      end

      def stri(str)
        #str.gsub!(/-/,"\-")
        key_chars = str.split(//)
        key_chars.collect! do |char|
          if char.eql?("-")
            match["#{Regexp.escape("\x2d")}"]
          else
            match["#{char.upcase}#{char.downcase}"]
          end
        end
        key_chars.reduce(:>>)
      end
    end

    include Rules
  end
end
