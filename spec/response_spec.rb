require "spec_helper"
require "http/security/response"

describe Response do
  describe "#initialize" do
    subject do
      described_class.new(
      )
    end
  end

  describe ".parse" do
    let(:response) do
      {
        "Cache-Control" => "no-cache, no-store, must-revalidate, pre-check=0, post-check=0",
        "Content-Length" => "12682",
        "Content-Security-Policy" => "default-src https:; connect-src https:; font-src https: data:; frame-src https: twitter:; img-src https: data:; media-src https:; object-src https:; script-src 'unsafe-inline' 'unsafe-eval' https:; style-src 'unsafe-inline' https:; report-uri https://twitter.com/i/csp_report?a=NVQWGYLXFVZXO2LGOQ%3D%3D%3D%3D%3D%3D&ro=false;",
        "Content-Type" => "text/html;charset=utf-8",
        "Date" => "Thu, 20 Nov 2014 00:27:36 UTC",
        "Expires" => "Tue, 31 Mar 1981 05:00:00 GMT",
        "Last-Modified" => "Thu, 20 Nov 2014 00:27:36 GMT",
        "Ms" => "A",
        "Pragma" => "no-cache",
        "Server" => "tsa_b",
        "Set-Cookie" => 
        "_twitter_sess=BAh7CSIKZmxhc2hJQzonQWN0aW9uQ29udHJvbGxlcjo6Rmxhc2g6OkZsYXNo%250ASGFzaHsABjoKQHVzZWR7ADoPY3JlYXRlZF9hdGwrCOzcmMpJAToMY3NyZl9p%250AZCIlYmEzNTQ5YzM0MzYwZjAzZWMwMTFmZDY3MzVhMjE0MzM6B2lkIiUxMzI3%250AY2M1OWIyYzM3N2IzMmYxZWZiNmJlN2ZmYzdjZQ%253D%253D--09c51d06332d2b4cf102948a3f0491131ed952fa; Path=/; Domain=.twitter.com; Secure; HTTPOnly, guest_id=v1%3A141644325604142464; Domain=.twitter.com; Path=/; Expires=Sat, 19-Nov-2016 00:27:36 UTC",
        "Status" => "200 OK",
        "Strict-Transport-Security" => "max-age=631138519",
        "X-Connection-Hash" => "f58cf3aa568cfd2abfd6a259c85a453b",
        "X-Content-Type-Options" => "nosniff",
        "X-Frame-Options" => "SAMEORIGIN",
        "X-Transaction" => "a0c1a67d4d799176",
        "X-Ua-Compatible" => "IE=edge,chrome=1",
        "X-Xss-Protection" => "1; mode=block"
      }
    end

    subject { described_class.parse(response) }

    it "should parse Cache-Control" do
    end

    it "should parse Content-Security-Policy" do
    end

    it "should parse Content-Security-Policy-Report-Only" do
    end

    it "should parse Expires" do
    end

    it "should parse Pragma" do
    end

    it "should parse Strict-Transport-Security" do
    end

    it "should parse X-Content-Type-Options" do
    end

    it "should parse X-Frame-Options" do
    end

    it "should parse X-Permitted-Cross-Domain-Policies" do
    end

    it "should parse X-XSS-Protection" do
    end

    context "Alexa 100", :gauntlet do
      require 'csv'
      require 'net/http'

      path = File.expand_path('../data/alexa.csv', __FILE__)
      csv  = CSV.new(open(path), headers: false)

      csv.each do |row|
        rank, domain = row[0].to_i, row[1].downcase

        context domain do
          it "should not raise a ParseError" do
            begin
              response = Net::HTTP.get_response(URI("http://#{domain}/"))

              expect {
                described_class.parse(response)
              }.to_not raise_error(Parslet::ParseError)
            rescue => error
              pending error.message
            end
          end
        end
      end
    end
  end
end
