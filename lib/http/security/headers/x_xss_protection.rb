module HTTP
  module Security
    module Headers
      class XXSSProtection

        attr_reader :mode

        def initialize(directives={})
          @enabled = directives[:enabled]
          @mode    = directives[:mode]
        end

        def enabled?
          @enabled
        end

        def to_s
          str = if @enabled then '1'
                else             '0'
                end

          str << "; mode=#{@mode}" if @mode

          return str
        end

      end
    end
  end
end
