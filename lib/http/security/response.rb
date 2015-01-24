require 'http/security/parsers'
require 'http/security/malformed_header'

module HTTP
  module Security
    class Response

      # The parsed `Cache-Control` header.
      attr_reader :cache_control

      # The parsed `Content-Security-Policy` header.
      attr_reader :content_security_policy

      # The parsed `Content-Security-Policy-Report-Only` header.
      attr_reader :content_security_policy_report_only

      # The parsed `Expires` header.
      attr_reader :expires

      # The parsed `Pragma` header.
      attr_reader :pragma

      # The parsed `Set-Cookie` header.
      attr_reader :set_cookie

      # The parsed `Strict-Transport-Security` header.
      attr_reader :strict_transport_security

      # The parsed `X-Content-Type-Options` header.
      attr_reader :x_content_type_options
      alias content_type_options x_content_type_options

      # The parsed `X-Frame-Options` header.
      attr_reader :x_frame_options
      alias frame_options x_frame_options

      # The parsed `X-Permitted-Cross-Domain-Policies` header.
      attr_reader :x_permitted_cross_domain_policies
      alias permitted_cross_domain_policies x_permitted_cross_domain_policies

      # The parsed `X-XSS-Protection` header.
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
        'Strict-Transport-Security'           => Parsers::StrictTransportSecurity,
        'Set-Cookie'                          => Parsers::SetCookie,
        'X-Content-Type-Options'              => Parsers::XContentTypeOptions,
        'X-Frame-Options'                     => Parsers::XFrameOptions,
        'X-Permitted-Cross-Domain-Policies'   => Parsers::XPermittedCrossDomainPolicies,
        'X-Xss-Protection'                    => Parsers::XXSSProtection
      }

      # Header names and their corresponding fields.
      HEADERS = {
        'Cache-Control'                       => :cache_control,
        'Content-Security-Policy'             => :content_security_policy,
        'Content-Security-Policy-Report-Only' => :content_security_policy_report_only,
        'Expires'                             => :expires,
        'Pragma'                              => :pragma,
        'Strict-Transport-Security'           => :strict_transport_security,
        'Set-Cookie'                          => :set_cookie,
        'X-Content-Type-Options'              => :x_content_type_options,
        'X-Frame-Options'                     => :x_frame_options,
        'X-Permitted-Cross-Domain-Policies'   => :x_permitted_cross_domain_policies,
        'X-Xss-Protection'                    => :x_xss_protection
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

        HEADERS.each do |name,field|
          if (value = response[name])
            fields[field] = begin
                              parse_header(name,value)
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

        HEADERS.each do |name,field|
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
      # @raise [Parslet::ParseFailed]
      #   The header was malformed.
      #
      def self.parse_header(name,value)
        PARSERS.fetch(name).parse(value)
      end

    end
  end
end
