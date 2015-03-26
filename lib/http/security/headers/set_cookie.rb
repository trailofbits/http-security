module HTTP
  module Security
    module Headers
      class SetCookie

        include Enumerable

        # @return [Array<Cookie>]
        attr_reader :cookies

        class Cookie

          attr_reader :cookie

          attr_reader :path

          attr_reader :domain

          attr_reader :expires

          def initialize(directives={})
            @cookie    = directives[:cookie]
            @path      = directives[:path]
            @domain    = directives[:domain]
            @expires   = directives[:expires]
            @secure    = directives[:secure]
            @http_only = directives[:http_only]
          end

          def name
            @cookie.keys.first
          end

          def value
            @cookie.values.first
          end

          def secure?
            !!@secure
          end

          def http_only?
            !!@http_only
          end

          def to_s
            str = "#{name}=#{value}"

            str << "; Path=#{@path}"                if @path
            str << "; Domain=#{@domain}"            if @domain
            str << "; Expires=#{@expires.httpdate}" if @expires
            str << "; Secure"                       if @secure
            str << "; HttpOnly"                     if @http_only

            return str
          end

        end

        def initialize(cookies=[])
          @cookies = cookies.map { |cookie| Cookie.new(cookie) }
        end

        def each(&block)
          @cookies.each(&block)
        end

        def to_s
          @cookies.map(&:to_s).join(', ')
        end

      end
    end
  end
end
