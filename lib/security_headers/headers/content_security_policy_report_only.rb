require 'security_headers/headers/content_security_policy'

module SecurityHeaders
  class ContentSecurityPolicyReportOnly < ContentSecurityPolicy
    module Rules
      def self.included(base)
        base.header_rule("Content-Security-Policy-Report-Only") do
          csp_pattern
        end
      end
    end
    include Rules
  end
end
