require 'security_headers/parsers/parser'

module SecurityHeaders
  module Parsers
    class XPermittedCrossDomainPolicies < Parser
      # X-Permitted-Cross-Domain-Policies
      # Syntax:
      # X-Permitted-Cross-Domain-Policies = "none"
      #                    | master-only
      #                    | by-content-type
      #                    | by-ftp-filename
      #                    | all
      rule(:x_permitted_cross_domain_policies) do
        stri("none")            |
        stri("master-only")     |
        stri("by-content-type") |
        stri("by-ftp-filename") |
        stri("all")
      end
      root :x_permitted_cross_domain_policies
    end
  end
end
