require 'http/security/parsers'

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
        @x_content_type_options = headers[:x_content_type_options]
        @x_frame_options = headers[:x_frame_options]
        @x_permitted_cross_domain_policies = headers[:x_permitted_cross_domain_policies]
        @x_xss_protection = headers[:x_xss_protection]
      end

      HEADERS = [
        [:cache_control, 'Cache-Control', Parsers::CacheControl],
        [:content_security_policy, 'Content-Security-Policy', Parsers::ContentSecurityPolicy],
        [:content_security_policy_report_only, 'Content-Security-Policy-Report-Only', Parsers::ContentSecurityPolicyReportOnly],
        [:expires, 'Expires', Parsers::Expires],
        [:pragma, 'Pragma', Parsers::Pragma],
        [:strict_transport_security, 'Strict-Transport-Security', Parsers::StrictTransportSecurity],
        [:x_content_type_options, 'X-Content-Type-Options', Parsers::XContentTypeOptions],
        [:x_frame_options, 'X-Frame-Options', Parsers::XFrameOptions],
        [:x_permitted_cross_domain_policies, 'X-Permitted-Cross-Domain-Policies', Parsers::XPermittedCrossDomainPolicies],
        [:x_xss_protection, 'X-XSS-Protection', Parsers::XXSSProtection]
      ].freeze

      #
      # Parses the HTTP security headers of a HTTP response.
      #
      # @param [#[]] response
      #   An HTTP response object. Must provide access to headers via the `#[]`
      #   method.
      #
      # @return [Response]
      #
      # @api public
      #
      def self.parse(response)
        fields = {}

        HEADERS.each do |name,header,parser|
          if (value = response[header])
            fields[name] = parser.parse(value)
          end
        end

        return new(fields)
      end

    end
  end
end
