require 'security_headers/headers/content_security_policy'

module SecurityHeaders
  class ContentSecurityPolicyReportOnly < ContentSecurityPolicy

    header_rule("Content-Security-Policy-Report-Only") do
      csp_pattern
    end

  end
end
