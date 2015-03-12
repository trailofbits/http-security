module HTTP
  module Security
    module Headers
      class CacheControl

        attr_reader :max_age

        def initialize(options={})
          @private  = options[:private]
          @max_age  = options[:max_age]
          @no_cache = options[:no_cache]
        end

        def private?
          @private
        end

        def no_cache?
          @no_cache
        end

        def to_s
          [
            "private"             if @private,
            "max_age=#{@max_age}" if @max_age,
            "no-cache"            if @no_cache
          ].compact.join(', ')
        end

      end
    end
  end
end
