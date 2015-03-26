module HTTP
  module Security
    module Headers
      class XPermittedCrossDomainPolicies

        def initialize(directives={})
          @none            = directives[:none]
          @master_only     = directives[:master_only]
          @by_content_type = directives[:by_content_type]
          @by_ftp_filename = directives[:by_ftp_filename]
          @all             = directives[:all]
        end

        def none?
          !!@none
        end

        def master_only?
          !!@master_only
        end

        def by_content_type?
          !!@by_content_type
        end

        def by_ftp_filename?
          !!@by_ftp_filename
        end

        def all?
          !!@all
        end

        def to_s
          if    @none            then 'none'
          elsif @master_only     then 'master-only'
          elsif @by_content_type then 'by-content-type'
          elsif @by_ftp_filename then 'by-ftp-filename'
          elsif @all             then 'all'
          else                        ''
          end
        end

      end
    end
  end
end
