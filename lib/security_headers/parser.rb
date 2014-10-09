require 'parslet'
require 'security_headers/utilities'
module SecurityHeaders
  class Parser < Parslet::Parser
    root :security_headers

    rule(:security_headers) do
      (security_header).repeat >>
      header_sep.maybe
    end

    rule(:header_sep) { wsp? >> str(';') >> wsp? }

    rule(:security_header) do
      x_frame_options
    end

    def self.header_rule(tag, &block)
      name = header_to_sym(tag)
      rule(:"#{name}") do
        str(tag) >> str(':') >> wsp? >>
        (instance_eval(&block).as(name) | unknown_header)
      end
    end

    header_rule('X-Frame-Options') do
      str('deny') | str('sameorigin')
    end

    rule(:unknown_tag) { match["^; \t"].repeat(1) }
    rule(:unknown_header) { match["^=; \t"].repeat(1) }

    rule(:hex) { digit | match('[a-fA-F]') }
    rule(:alphanum) { alpha | digit }
    rule(:alpha) { match('[a-zA-Z]') }
    rule(:digit) { match('[0-9]') }
    rule(:wsp) { str(' ') | str("\t") }
    rule(:wsp?) { wsp.repeat }
  end

  class << self
    private
    def header_to_sym(header)
      header.downcase.gsub("-","_").to_sym
    end
  end
end
