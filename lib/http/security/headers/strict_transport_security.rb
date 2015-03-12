module HTTP
  module Security
    module Headers
      class StrictTransportSecurity

        attr_reader :max_age

        def initialize(directives={})
          @max_age             = directives[:max_age]
          @include_sub_domains = directives[:includesubdomains]
        end

        def include_sub_domains?
          @include_sub_domains
        end

        def to_str
          [
            "max-age=#{@max_age}" if @max_age,
            "includeSubDomains" if @include_sub_domains
          ].compact.join('; ')
        end

      end
    end
  end
end
