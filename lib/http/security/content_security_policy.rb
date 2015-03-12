module HTTP
  module Security
    class ContentSecurityPolicy

      attr_reader :default_src

      attr_reader :script_src

      attr_reader :object_src

      attr_reader :style_src

      attr_reader :img_src

      attr_reader :media_src

      attr_reader :frame_src

      attr_reader :font_src

      attr_reader :connect_src

      # @return [Array<URI>]
      attr_reader :report_uri

      attr_reader :sandbox

      def initialize(directives={})
        @default_src = directives[:default_src]
        @script_src = directives[:script_src]
        @object_src = directives[:object_src]
        @style_src = directives[:style_src]
        @img_src = directives[:img_src]
        @media_src = directives[:media_src]
        @frame_src = directives[:frame_src]
        @font_src = directives[:font_src]
        @connect_src = directives[:connect_src]

        @report_uri = Array(directives[:report_uri])
        @sandbox    = directives[:sandbox]
      end

      def to_s
        [
          "default-src #{@default_src}" if @default_src,
          "; script-src #{@script_src}" if @script_src,
          "; object-src #{@object_src}" if @object_src,
          "; style-src #{@style_src}"   if @style_src,
          "; image-src #{@image_src}"   if @image_src,
          "; media-src #{@media_src}"   if @media_src,
          "; frame-src #{@frame_src}"   if @frame_src,
          "; font-src #{@font_src}"     if @font_src,
          "; connect-src #{@connect_src}" if @connect_src,

          "; sandbox #{@sandbox}"                 if @sandbox,
          "; report-uri #{@report_uri.join(' ')}" unless @report_uri.empty?
        ].compact.join(', ')
      end

    end
  end
end
