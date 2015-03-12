module HTTP
  module Security
    class Pragma

      def initialize(directives={})
        @no_cache = directives[:no_cache]
      end

      def no_cache?
        @no_cache
      end

      def to_s
        str = ''
        str << 'no-cache' if @no_cache

        return str
      end

    end
  end
end
