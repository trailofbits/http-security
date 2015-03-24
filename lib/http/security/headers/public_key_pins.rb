module HTTP
  module Security
    module Headers
      class PublicKeyPins

        # @return [Hash{Symbol,String => Array<String>}]
        attr_reader :pin

        # @return [Integer]
        attr_reader :max_age

        # @return [URI::HTTP]
        attr_reader :report_uri

        def initialize(options={})
          @pin = {}

          options.each do |key,value|
            if (key.kind_of?(Symbol) && key =~ /^pin_/)
              @pin[key[4..-1].to_sym] = Array(value)
            elsif (key.kind_of?(String) && key.start_with?('pin-'))
              @pin[key[4..-1]] = Array(value)
            end
          end

          @max_age             = options[:max_age]
          @include_sub_domains = options[:includesubdomains]
          @report_uri          = options[:report_uri]
          @strict              = options[:strict]
        end

        def include_sub_domains?
          @include_sub_domains
        end

        def strict?
          @strict
        end

        def to_s
          directives = []

          @pin.each do |algorithm,fingerprints|
            Array(fingerprints).each do |fingerprint|
              directives << "pin-#{algorithm}=#{fingerprint.dump}"
            end
          end

          directives << "max-age=#{@max_age}"           if @max_age
          directives << "includeSubdomains"             if @include_sub_domains
          directives << "report-uri=\"#{@report_uri}\"" if @report_uri
          directives << "strict"                        if @strict

          return directives.join('; ')
        end

      end
    end
  end
end
