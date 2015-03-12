module HTTP
  module Security
    class XContentTypeOptions

      def initialize(directives={})
        @no_sniff = directives[:nosniff]
      end

      def no_sniff?
        @no_sniff
      end

      def to_s
        str = ''
        str << "nosniff" if @no_sniff

        return str
      end

    end
  end
end
