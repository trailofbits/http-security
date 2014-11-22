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
        (
          none            |
          master_only     |
          by_content_type |
          by_ftp_filename |
          all
        ).as(:directives)
      end
      root :x_permitted_cross_domain_policies

      directive_rule :none
      directive_rule :master_only, 'master-only'
      directive_rule :by_content_type, 'by-content-type'
      directive_rule :by_ftp_filename, 'by-ftp-filename'
      directive_rule :all
    end
  end
end
