module HTTP
  module Security
    module Headers
      class XFrameOptions

        attr_reader :allow_from

        def initialize(directives={})
          @deny        = directives[:deny]
          @same_origin = directives[:sameorigin]
          @allow_from  = directives[:allow_from]
          @allow_all   = directives[:allowall]
        end

        def deny?
          !!@deny
        end

        def same_origin?
          !!@same_origin
        end

        def allow_all?
          !!@allow_all
        end

        def to_s
          if    @deny        then 'DENY'
          elsif @same_origin then 'SAMEORIGIN'
          elsif @allow_from  then "ALLOW-FROM #{@allow_from}"
          elsif @allow_all   then 'ALLOWALL'
          else                    ''
          end
        end

      end
    end
  end
end
