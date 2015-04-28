require 'parslet'

module HTTP
  module Security
    class InvalidHeader < Parslet::ParseFailed
    end
  end
end
