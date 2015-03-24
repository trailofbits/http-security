require 'http/security/http_date'

require "parslet"
require 'uri'

module HTTP
  module Security
    module Parsers
      class Parser < Parslet::Parser
        def self.character_match_rule(name, character)
          rule(name) do
            wsp? >> str(character) >> wsp?
          end
        end

        def self.directive_rule(name,string=nil)
          string ||= name.to_s.tr('_','-')

          rule(name) do
            stri(string).as(:name)
          end
        end

        def self.field_directive_rule(name,directive)
          rule(name) do
            stri(directive).as(:name) >> (equals >> field_name.as(:value)).maybe
          end
        end

        def self.numeric_directive_rule(name,directive)
          rule(name) do
            stri(directive).as(:name) >> equals >> (
              digits.as(:numeric) |
              (s_quote >> digits.as(:numeric) >> s_quote) |
              (d_quote >> digits.as(:numeric) >> d_quote)
            ).as(:value)
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

        #
        # Directive Helpers
        #
        numeric_directive_rule :max_age, "max-age"
        numeric_directive_rule :max_stale, "max-stale"
        numeric_directive_rule :min_fresh, "min-fresh"
        numeric_directive_rule :s_maxage, "s-maxage"
        character_match_rule :equals, "="
        character_match_rule :s_quote, "'"
        character_match_rule :d_quote, '"'
        character_match_rule :semicolon, ";"
        character_match_rule :comma, ","

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
          (
            rfc1123_date |
            rfc850_date  |
            asctime_date
          ).as(:date)
        end

        rule(:rfc1123_date) do
          wkday >> str(",") >> wsp >> date1 >> wsp >> time >> wsp >> zone
        end

        rule(:rfc850_date) do
          weekday >> str(",") >> wsp >> date2 >> wsp >> time >> wsp >> zone
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

        rule(:zone) do
          str('UT') | str('GMT')  | # Universal Time
                                    # North American : UT
          str('EST') | str('EDT') | #   Eastern:  - 5/ - 4
          str('CST') | str('CDT') | #   Central:  - 6/ - 5
          str('MST') | str('MDT') | #   Mountain: - 7/ - 6
          str('PST') | str('PDT') | #   Pacific:  - 8/ - 7
          alpha |                   # Military: Z = UT;
                                    #   A:-1; (J not used)
                                    #   M:-12; N:+1; Y:+12
          match['+-'] >> four_digit # Local differential
                                    #   hours+min. (HHMM)
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

        rule(:uri) {
          (
            scheme_fragment.maybe >>
            (user_info >> str("@")).maybe >>
            host_name >>
            (str(":") >> digits).maybe >>
            uri_path
          ).as(:uri)
        }

        rule(:user_info) {
          (
            unreserved | pct_encoded | sub_delims | str(":")
          ).repeat(0)
        }

        rule(:unreserved) { alpha | digit | str("-") | str(".") | str("_") | str("~") }
        rule(:pct_encoded) { str("%") >> hex_digit >> hex_digit }
        rule(:sub_delims) { match[Regexp.escape("!$&'()*+,;=")] }
        rule(:pchar) { unreserved | pct_encoded | sub_delims | str("@") | str(":") }


        rule(:fragment) { (pchar | str("/") | str("?")).repeat(0) }
        rule(:query) { fragment }
        rule(:path) { pchar.repeat(1) >> (str('/') >> pchar.repeat).repeat }

        rule(:paramchar) { str(";").absent? >> pchar }
        rule(:param) { (paramchar).repeat }
        rule(:params) { param >> (str(';') >> param).repeat }

        rule(:uri_path) {
          (str('/').maybe >> path.maybe) >>
          (str(';') >> params).maybe >>
          (str('?') >> query).maybe >>
          (str('#') >> fragment).maybe
        }

        rule(:header_extension) do
          token.as(:name) >> (equals >> ( token | quoted_string).as(:value)).maybe
        end

        #
        # Basic Rules
        #
        # RFC 2616, Section 2.2
        #
        rule(:digit) { match["0-9"] }
        rule(:digits) { digit.repeat(1) }
        rule(:hex_digit) { match['0-9a-fA-F'] }
        rule(:upper) { match['A-Z'] }
        rule(:lower) { match['a-z'] }
        rule(:alpha) { match['a-zA-Z'] }
        rule(:alnum) { match['a-zA-Z0-9'] }
        rule(:cntrl) { match["\x00-\x1f"] }
        rule(:ascii) { match["\x00-\x7f"] }
        rule(:wsp) { match[" \t"] }
        rule(:wsp?) { wsp.repeat }
        rule(:crlf)  { str("\r\n") }
        rule(:lws) { crlf.maybe >> wsp.repeat(1) }

        #1*<any (US-ASCII) CHAR except SPACE, CTLs, or separators>
        rule(:token) do
          match[
            # 
            '^\x00-\x1f\x7f' +                      # no CTLs
            '\x20' +                                # no SPACE
            Regexp.escape("()<>@,;:\\\"/[]?={} \t") # no separators
          ].repeat(1)
        end

        rule(:quoted_string) do
          d_quote >> (qdtext | quoted_pair).repeat(0).as(:string) >> d_quote
        end
        rule(:qdtext) do
          match['^\x00-\x1f\x22\x7f'] | lws
        end

        rule(:quoted_pair) do
          str('\\') >> ascii.as(:escaped_char)
        end

        rule(:field_name) do
          valid_field_name | ( d_quote >> valid_field_name >> d_quote )
        end

        rule(:valid_field_name) do
          (
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
          ).as(:field)
        end

        #
        # URI Elements
        #
        rule(:scheme_fragment) { (scheme >> str(":") >> str("//")).maybe }
        rule(:scheme)    { ( alpha | digit ).repeat }
        rule(:host_name) { ( alnum | match("[-_.]") ).repeat(1) }

        class Transform < Parslet::Transform

          rule(boolean: simple(:bool)) do
            case bool
            when '0', 'no', 'false' then false
            when '1', 'yes', 'true' then true
            end
          end
          rule(numeric: simple(:numeric)) { Integer(numeric) }

          ESCAPED_CHARS = {
            '0' => "\0",
            'a' => "\a",
            'b' => "\b",
            't' => "\t",
            'n' => "\n",
            'v' => "\v",
            'f' => "\f",
            'r' => "\r"
          }
          ESCAPED_CHARS.default_proc = proc { |hash,key| key }

          rule(escaped_char: simple(:char)) { ESCAPED_CHARS[char] }
          rule(string: simple(:text))       { text }
          rule(string: sequence(:strings))  { strings.join }

          rule(date: simple(:date))       { HTTPDate.parse(date.to_s) }
          rule(uri: simple(:uri))         { URI.parse(uri) }

          rule(list: simple(:element))  { [element] }
          rule(list: subtree(:elements)) do
            case elements
            when Array then elements
            else            [elements]
            end
          end

          rule(name: simple(:name)) do
            {name.to_s.downcase.tr('-','_').to_sym => true}
          end
          rule(name: simple(:name), value: simple(:value)) do
            {name.to_s.downcase.tr('-','_').to_sym => value}
          end

          rule(name: simple(:name), values: subtree(:values)) do
            {name.to_s.downcase.tr('-','_').to_sym => values}
          end

          rule(directives: subtree(:hashes)) do
            case hashes
            when Array
              hashes.reduce do |hash,sub_hash|
                hash.merge!(sub_hash) do |key,old_value,new_value|
                  case old_value
                  when Array then old_value << new_value
                  when nil   then new_value
                  else            [old_value, new_value]
                  end
                end
              end
            else
              hashes
            end
          end

        end

        def parse(string)
          Transform.new.apply(super(string))
        end

        def self.parse(string)
          new.parse(string)
        end

      end
    end
  end
end
