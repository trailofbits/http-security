require 'http/security/exceptions'
require 'http/security/parsers'
require 'http/security/headers'
require 'http/security/malformed_header'

module HTTP
  module Security
    class Response

      include Enumerable

      # The parsed `Cache-Control` header.
      #
      # @return [Headers::CacheControl]
      attr_reader :cache_control

      # The parsed `Content-Security-Policy` header.
      #
      # @return [Headers::ContentSecurityPolicy]
      attr_reader :content_security_policy

      # The parsed `Content-Security-Policy-Report-Only` header.
      #
      # @return [Headers::ContentSecurityPolicyReportOnly]
      attr_reader :content_security_policy_report_only

      # The parsed `Expires` header.
      #
      # @return [HTTPDate]
      attr_reader :expires

      # The parsed `Pragma` header.
      #
      # @return [Headers::Pagram]
      attr_reader :pragma

      # The parsed `Set-Cookie` header.
      #
      # @return [Headers::SetCookie]
      attr_reader :set_cookie

      # The parsed `Strict-Transport-Security` header.
      #
      # @return [Headers::StrictTransportSecurity]
      attr_reader :strict_transport_security

      # The parsed `Public-Key-Pins` header.
      #
      # @return [Headers::PublicKeyPin]
      attr_reader :public_key_pins

      # The parsed `Public-Key-Pins-Report-Only` header.
      #
      # @return [Headers::PublicKeyPinsReportOnly]
      attr_reader :public_key_pins_report_only

      # The parsed `X-Content-Type-Options` header.
      #
      # @return [Headers::XContentTypeOptions]
      attr_reader :x_content_type_options
      alias content_type_options x_content_type_options

      # The parsed `X-Frame-Options` header.
      #
      # @return [Headers::XFrameOptions]
      attr_reader :x_frame_options
      alias frame_options x_frame_options

      # The parsed `X-Permitted-Cross-Domain-Policies` header.
      #
      # @return [Headers::XPermittedCrossDomainPolicies]
      attr_reader :x_permitted_cross_domain_policies
      alias permitted_cross_domain_policies x_permitted_cross_domain_policies

      # The parsed `X-XSS-Protection` header.
      #
      # @return [Headers::XXssProtection]
      attr_reader :x_xss_protection
      alias xss_protection x_xss_protection

      #
      # Initializes the response.
      #
      # @param [Hash{Symbol => Object}] headers
      #   The parsed headers.
      #
      # @option options [Hash] :cache_control
      #   The parsed `Cache-Control` header.
      #
      # @option options [Hash] :content_security_policy
      #   The parsed `Content-Security-Policy` header.
      #
      # @option options [Hash] :content_security_policy_report_only
      #   The parsed `Content-Security-Policy-Report-Only` header.
      #
      # @option options [Hash] :expires
      #   The parsed `Expires` header.
      #
      # @option options [Hash] :pragma
      #   The parsed `Pragma` header.
      #
      # @option options [Hash] :strict_transport_security
      #   The parsed `Strict-Transport-Security` header.
      #
      # @option options [Array<Hash>] :set_cookie
      #   The parsed `Set-Cookie` header.
      #
      # @option options [Hash] :public_key_pins
      #   The parsed `Public-Key-Pins` header.
      #
      # @option options [Hash] :public_key_pins_report_only
      #   The parsed `Public-Key-Pins-Report-Only` header.
      #
      # @option options [Hash] :x_content_type_options
      #   The parsed `X-Content-Type-Options` header.
      #
      # @option options [Hash] :x_frame_options
      #   The parsed `X-Frame-Options` header.
      #
      # @option options [Hash] :x_permitted_cross_domain_policies
      #   The parsed `X-Permitted-Cross-Domain-Policies` header.
      #
      # @option options [Hash] :x_xss_protection
      #   The parsed `X-XSS-Protection` header.
      #
      # @api semipublic
      #
      def initialize(headers={})
        @cache_control = headers[:cache_control]
        @content_security_policy = headers[:content_security_policy]
        @content_security_policy_report_only = headers[:content_security_policy_report_only]
        @expires = headers[:expires]
        @pragma = headers[:pragma]
        @public_key_pins = headers[:public_key_pins]
        @public_key_pins_report_only = headers[:public_key_pins_report_only]
        @strict_transport_security = headers[:strict_transport_security]
        @set_cookie = headers[:set_cookie]
        @x_content_type_options = headers[:x_content_type_options]
        @x_frame_options = headers[:x_frame_options]
        @x_permitted_cross_domain_policies = headers[:x_permitted_cross_domain_policies]
        @x_xss_protection = headers[:x_xss_protection]
      end

      # Header names and their corresponding parsers.
      PARSERS = {
        'Cache-Control'                       => Parsers::CacheControl,
        'Content-Security-Policy'             => Parsers::ContentSecurityPolicy,
        'Content-Security-Policy-Report-Only' => Parsers::ContentSecurityPolicyReportOnly,
        'Expires'                             => Parsers::Expires,
        'Pragma'                              => Parsers::Pragma,
        'Public-Key-Pins'                     => Parsers::PublicKeyPins,
        'Public-Key-Pins-Report-Only'         => Parsers::PublicKeyPinsReportOnly,
        'Strict-Transport-Security'           => Parsers::StrictTransportSecurity,
        'Set-Cookie'                          => Parsers::SetCookie,
        'X-Content-Type-Options'              => Parsers::XContentTypeOptions,
        'X-Frame-Options'                     => Parsers::XFrameOptions,
        'X-Permitted-Cross-Domain-Policies'   => Parsers::XPermittedCrossDomainPolicies,
        'X-Xss-Protection'                    => Parsers::XXSSProtection
      }

      # Header names and their corresponding classes
      HEADERS = {
        'Cache-Control'                       => Headers::CacheControl,
        'Content-Security-Policy'             => Headers::ContentSecurityPolicy,
        'Content-Security-Policy-Report-Only' => Headers::ContentSecurityPolicyReportOnly,
        'Expires'                             => nil,
        'Pragma'                              => Headers::Pragma,
        'Public-Key-Pins'                     => Headers::PublicKeyPins,
        'Public-Key-Pins-Report-Only'         => Headers::PublicKeyPinsReportOnly,
        'Strict-Transport-Security'           => Headers::StrictTransportSecurity,
        'Set-Cookie'                          => Headers::SetCookie,
        'X-Content-Type-Options'              => Headers::XContentTypeOptions,
        'X-Frame-Options'                     => Headers::XFrameOptions,
        'X-Permitted-Cross-Domain-Policies'   => Headers::XPermittedCrossDomainPolicies,
        'X-Xss-Protection'                    => Headers::XXSSProtection
      }

      # Header names and their corresponding fields.
      FIELDS = {
        'Cache-Control'                       => :cache_control,
        'Content-Security-Policy'             => :content_security_policy,
        'Content-Security-Policy-Report-Only' => :content_security_policy_report_only,
        'Expires'                             => :expires,
        'Pragma'                              => :pragma,
        'Public-Key-Pins'                     => :public_key_pins,
        'Public-Key-Pins-Report-Only'         => :public_key_pins_report_only,
        'Strict-Transport-Security'           => :strict_transport_security,
        'Set-Cookie'                          => :set_cookie,
        'X-Content-Type-Options'              => :x_content_type_options,
        'X-Frame-Options'                     => :x_frame_options,
        'X-Permitted-Cross-Domain-Policies'   => :x_permitted_cross_domain_policies,
        'X-Xss-Protection'                    => :x_xss_protection,
      }

      #
      # Parses the HTTP security headers of a HTTP response.
      #
      # @param [#[]] response
      #   An HTTP response object. Must provide access to headers via the `#[]`
      #   method.
      #
      # @return [Response]
      #   The parsed response.
      #
      # @api public
      #
      def self.parse(response)
        fields = {}

        FIELDS.each do |header,field|
          if (value = response[header])
            fields[field] = begin
                              parse_header(header,value)
                            rescue Parslet::ParseFailed => error
                              MalformedHeader.new(value,error.cause)
                            end
          end
        end

        return new(fields)
      end

      #
      # Parses the HTTP security headers of a HTTP response.
      #
      # @param [#[]] response
      #   An HTTP response object. Must provide access to headers via the `#[]`
      #   method.
      #
      # @return [Response]
      #
      # @raise [Parslet::ParseFailed]
      #   One of the headers was malformed.
      #
      # @api public
      #
      def self.parse!(response)
        fields = {}

        FIELDS.each do |name,field|
          if (value = response[name])
            fields[field] = parse_header(name,value)
          end
        end

        return new(fields)
      end

      #
      # Parses an individual header.
      #
      # @param [String] name
      #   The header name.
      #
      # @param [String] value
      #   The raw value of the header.
      #
      # @return [Hash]
      #   The parsed header data.
      #
      # @raise [InvalidHeader]
      #   The header was malformed.
      #
      def self.parse_header(name,value)
        parser = PARSERS.fetch(name)
        value  = begin
                   parser.parse(value)
                 rescue Parslet::ParseFailed => error
                   raise(InvalidHeader.new(error.message,error.cause))
                 end

        if (header = HEADERS[name])
          header.new(value)
        else
          value
        end
      end

      #
      # Accesses an arbitrary security header.
      #
      # @param [String] header
      #   The canonical header name.
      #
      # @return [Object, nil]
      #   The parsed header value.
      #   
      def [](header)
        field = FIELDS.fetch(header)

        return instance_variable_get("@#{field}")
      end

      #
      # Enumerates over the parsed security header values.
      #
      # @yield [name, value]
      #   The given block will be passed each header name and parsed value.
      #
      # @yieldparam [String] name
      #   The canonical header name.
      #
      # @yieldparam [Object] value
      #   A header class from {Headers}.
      #
      # @return [Enumerator]
      #   If no block was given, an enumerator will be returned.
      #
      def each
        return enum_for(__method__) unless block_given?

        FIELDS.each do |header,field|
          if (value = self[header])
            yield header, value
          end
        end

        return self
      end

    end
  end
end
