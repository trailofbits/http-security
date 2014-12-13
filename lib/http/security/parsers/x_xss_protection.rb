require 'http/security/parsers/parser'

module HTTP
  module Security
    module Parsers
      class XXSSProtection < Parser
        # X-XSS-Protection
        # Syntax:
        # X-Content-Type-Options: < 1 | 0 >
        #                         /; mode=block
        rule(:x_xss_protection) do
          x_xss_flag >> (semicolon >> x_xss_mode).maybe >> (semicolon >> x_xss_report).maybe
        end
        root :x_xss_protection

        rule(:x_xss_flag) { match['01'].as(:boolean).as(:enabled) }
        rule(:x_xss_mode) do
          stri("mode") >> equals >> stri("block").as(:mode)
        end

        rule(:x_xss_report) do
          stri('report') >> equals >> any.repeat(1).as(:report)
        end
      end
    end
  end
end
