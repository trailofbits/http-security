require "parslet"
require "security_headers/headers/cache_control"
require "security_headers/headers/content_security_policy"
require "security_headers/headers/content_security_policy_report_only"
require "security_headers/headers/expires"
require "security_headers/headers/pragma"
require "security_headers/headers/strict_transport_security"
require "security_headers/headers/x_content_type_options"
require "security_headers/headers/x_frame_options"
require "security_headers/headers/x_permitted_cross_domain_policies"
require "security_headers/headers/x_xss_protection"

module SecurityHeaders
  class Parser < Parslet::Parser
    include BaseParser::Rules
    include CacheControl::Rules
    include ContentSecurityPolicy::Rules
    include ContentSecurityPolicyReportOnly::Rules
    include Expires::Rules
    include Pragma::Rules
    include StrictTransportSecurity::Rules
    include XContentTypeOptions::Rules
    include XFrameOptions::Rules
    include XPermittedCrossDomainPolicies::Rules
    include XXSSProtection::Rules

    root :security_headers
    rule(:security_headers) do
      header >> ( end_header_delimiter.absent? >> (header_sep >> header)).repeat(0) >>
        end_header_delimiter
    end

    rule(:header) do
      x_frame_options                     |
      strict_transport_security           |
      x_content_type_options              |
      x_xss_protection                    |
      cache_control                       |
      pragma                              |
      expires                             |
      x_permitted_cross_domain_policies   |
      content_security_policy_report_only |
      content_security_policy             |
      ignore_nonsecurity_header
    end

    rule(:end_header_delimiter) { str("\r\n\r\n") }
    rule(:header_sep) { str("\r\n") }
    rule(:ignore_nonsecurity_header) do
      (header_sep.absent? >> any).repeat(1).as(:excluded)
    end
  end
end
