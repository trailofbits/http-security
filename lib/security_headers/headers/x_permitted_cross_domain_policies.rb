require 'security_headers/headers/base_parser'

module SecurityHeaders
  class XPermittedCrossDomainPolicies < BaseParser
    module Rules
      def self.included(base)
        # X-Permitted-Cross-Domain-Policies
        # Syntax:
        # X-Permitted-Cross-Domain-Policies = "none"
        #                    | master-only
        #                    | by-content-type
        #                    | by-ftp-filename
        #                    | all
        base.header_rule("X-Permitted-Cross-Domain-Policies") do
          stri("none")            |
          stri("master-only")     |
          stri("by-content-type") |
          stri("by-ftp-filename") |
          stri("all")
        end
      end
    end
    include Rules
  end
end
