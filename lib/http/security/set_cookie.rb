module HTTP
  module Security
    class SetCookie

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
          !@secure.nil?
        end

        def http_only?
          !@http_only.nil?
        end

        def to_s
          str = "#{name}=#{value}"

          str << "; Path=#{@path}"                if @path
          str << "; Domain=#{@domain}"            if @domain
          str << "; Expires=#{@expires.httpdate}" if @domain
          str << "; Secure"                       if @secure
          str << "; HTTPOnly"                     if @http_only

          return str
        end

      end

      def initialize(cookies=[])
        @cookies = cookies.map { |cookie| Cookie.new(cookie) }
      end

      def to_s
        @cookies.map(&:to_s).join(', ')
      end

    end
  end
end
