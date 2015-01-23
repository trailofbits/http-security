module HTTP
  module Security
    class MalformedHeader

      # Raw value of the header.
      #
      # @return [String]
      attr_reader :value

      # Cause of the parser failure.
      #
      # @return [Parslet::Cause]
      attr_reader :cause

      #
      # Initializes the malformed header.
      #
      # @param [String] value
      #   The raw header value.
      #
      # @param [Parslet::Cause] cause
      #   The cause of the parser failure.
      #
      def initialize(value,cause)
        @value = value
        @cause = cause
      end

      alias value to_s

    end
  end
end
