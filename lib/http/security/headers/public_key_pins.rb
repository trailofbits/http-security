module HTTP
  module Security
    module Headers
      class PublicKeyPins

        # Expiration in seconds.
        #
        # @return [Integer]
        attr_reader :max_age

        # The report URI.
        #
        # @return [URI::HTTP]
        attr_reader :report_uri

        #
        # Initializes the `Public-Key-Pins` header.
        #
        # @param [Hash{Symbol => Object}] options
        # 
        def initialize(options={})
          @pin = {}

          options.each do |key,value|
            key = key.to_s

            if key.start_with?('pin_')
              @pin[key[4..-1].to_sym] = value
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

      end
    end
  end
end
