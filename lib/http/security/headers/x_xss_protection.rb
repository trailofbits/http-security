module HTTP
  module Security
    module Headers
      class XXSSProtection

        attr_reader :mode

        attr_reader :report

        def initialize(directives={})
          @enabled = directives[:enabled]
          @mode    = directives[:mode]
          @report  = directives[:report]
        end

        def enabled?
          @enabled
        end

        def to_s
          str = if @enabled then '1'
                else             '0'
                end

          str << "; mode=#{@mode}"     if @mode
          str << "; report=#{@report}" if @report

          return str
        end

      end
    end
  end
end
