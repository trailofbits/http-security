require 'date'

module HTTP
  module Security
    class HTTPDate < Date

      def to_s
        httpdate
      end

    end
  end
end
