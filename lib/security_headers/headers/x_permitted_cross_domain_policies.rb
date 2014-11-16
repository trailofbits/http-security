require 'security_headers/parser'

module SecurityHeaders
  class XPermitedCrossDomainPolicies < Parser

    # X-Permitted-Cross-Domain-Policies
    # Syntax:
    # X-Permitted-Cross-Domain-Policies = "none"
    #                    | master-only
    #                    | by-content-type
    #                    | by-ftp-filename
    #                    | all
    header_rule("X-Permitted-Cross-Domain-Policies") do
      stri("none")            |
      stri("master-only")     |
      stri("by-content-type") |
      stri("by-ftp-filename") |
      stri("all")
    end

  end
end
