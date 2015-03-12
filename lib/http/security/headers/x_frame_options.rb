module HTTP
  module Security
    module Headers
      class XFrameOptions

        attr_reader :allow_from

        def initialize(directives={})
          @deny        = directives[:deny]
          @same_origin = directives[:sameorigin]
          @allow_from  = directives[:allow_from]
        end

        def deny?
          @deny
        end

        def same_origin?
          @same_origin
        end

        def to_s
          if    @deny        then 'deny'
          elsif @same_origin then 'sameorigin'
          elsif @allow_from  then "allow-from #{@allow_from}"
          else                    ''
          end
        end

      end
    end
  end
end
