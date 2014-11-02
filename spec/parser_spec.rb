require "spec_helper"
require "security_headers/parser"
require 'curb'

describe Parser do
    describe "General parsing" do
    subject { described_class.new.security_headers }

    it "parses excess whitespace" do
      header = " X-Frame-Options : sameorigin\r\n\r\n"
      expect(subject.parse header).to eq(
        {x_frame_options: "sameorigin"}
      )
    end

    it "is case insensitive" do
      header = " X-Frame-OPTIONS : Sameorigin\r\n\r\n"
      expect(subject.parse header).to eq(
        {x_frame_options: "Sameorigin"}
      )
    end

    it "handles double quoted directive values" do
      header = "Strict-Transport-Security: max-age=\"0\"; includeSubDomains\r\n\r\n"
      expect(subject.parse header).to eq(
        {strict_transport_security: "max-age=\"0\"; includeSubDomains"}
      )
    end

    it "handles singled quoted directive values" do
      header = "Strict-Transport-Security: max-age='0'; includeSubDomains\r\n\r\n"
      expect(subject.parse header).to eq({strict_transport_security: "max-age='0'; includeSubDomains"})
    end

    it "handles multiple headers" do
      header = "X-XSS-Protection: 1; mode=block\r\nX-Frame-Options: SAMEORIGIN\r\n\r\n"
      expect(subject.parse header).to eq([
        {x_xss_protection: "1; mode=block"},
        {x_frame_options: "SAMEORIGIN"}
      ])
    end

    it "handles googles headers" do
      header = "Server: gws\r\n" \
      "Cache-Control: private, max-age=0\r\n" \
      "Content-Type: text/html; charset=ISO-8859-1\r\n" \
      "Alternate-Protocol: 80:quic,p=0.01\r\n" \
      "X-XSS-Protection: 1; mode=block\r\n" \
      "X-Frame-Options: SAMEORIGIN\r\n" \
      "Transfer-Encoding: chunked\r\n\r\n"
      expect(subject.parse header).to eq([
        {:excluded=>"Server: gws"},
        {cache_control: "private, max-age=0"},
        {:excluded=>"Content-Type: text/html; charset=ISO-8859-1"},
        {:excluded=>"Alternate-Protocol: 80:quic,p=0.01"},
        {x_xss_protection: "1; mode=block"},
        {x_frame_options: "SAMEORIGIN"},
        {:excluded=>"Transfer-Encoding: chunked"}
      ])
    end

    it "handles complex headers" do
      header = "HTTP/1.1 200 OK\r\nDate: Sun, 02 Nov 2014 16:04:05 GMT\r\nServer: Apache\r\nSet-Cookie: PHPSESSID=icn5fbnvnaju862a6upqm18f83; path=/; secure; HttpOnly\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nPragma: no-cache\r\nX-UA-Compatible: IE=edge,chrome=1\r\nLink: <https://prd.unicarehealth.com.au/>; rel=shortlink\r\nStrict-Transport-Security: max-age=31536000; includeSubdomains\r\nX-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\nX-XSS-Protection: 1; mode=block\r\nX-Permitted-Cross-Domain-Policies: master-only\r\nContent-Security-Policy-Report-Only: font-src data: 'self' https://fonts.gstatic.com ; img-src data: 'self' ; script-src 'unsafe-eval' 'unsafe-inline' 'self' ; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com ; connect-src 'self' ; default-src 'none' ; reflected-xss block; report-uri /wp-content/themes/scunicare/wac/csp-report.php?ro=false;\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n"
      expect(subject.parse header).to eq([
        {:excluded=>"HTTP/1.1 200 OK"},
        {:excluded=>"Date: Sun, 02 Nov 2014 16:04:05 GMT"},
        {:excluded=>"Server: Apache"},
        {:excluded=>"Set-Cookie: PHPSESSID=icn5fbnvnaju862a6upqm18f83; path=/; secure; HttpOnly"},
        {:expires=>"Thu, 19 Nov 1981 08:52:00 GMT"},
        {cache_control: "no-store, no-cache, must-revalidate, post-check=0, pre-check=0"},
        {:pragma => "no-cache"},
        {:excluded=>"X-UA-Compatible: IE=edge,chrome=1"},
        {:excluded=>"Link: <https://prd.unicarehealth.com.au/>; rel=shortlink"},
        {:strict_transport_security=>"max-age=31536000; includeSubdomains"},
        {:x_frame_options=>"DENY"},
        {:x_content_type_options=>"nosniff"},
        {x_xss_protection: "1; mode=block"},
        {:x_permitted_cross_domain_policies=>"master-only"},
        {:content_security_policy_report_only=>"font-src data: 'self' https://fonts.gstatic.com ; img-src data: 'self' ; script-src 'unsafe-eval' 'unsafe-inline' 'self' ; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com ; connect-src 'self' ; default-src 'none' ; reflected-xss block; report-uri /wp-content/themes/scunicare/wac/csp-report.php?ro=false;"},
        {:excluded=>"Content-Type: text/html; charset=UTF-8"}
      ])
    end

    it "handles stackoverflow headers" do
      header = "HTTP/1.1 200 OK\r\n" \
      "Cache-Control: public, no-cache=\"Set-Cookie\", max-age=1\r\n" \
      "Content-Length: 237857\r\n" \
      "Content-Type: text/html; charset=utf-8\r\n" \
      "Expires: Sun, 02 Nov 2014 19:32:00 GMT\r\n" \
      "Last-Modified: Sun, 02 Nov 2014 19:31:00 GMT\r\n" \
      "Vary: *\r\n" \
      "X-Frame-Options: SAMEORIGIN\r\n" \
      "Set-Cookie: prov=23def875-91bc-4a7b-a255-15544b6389d8; domain=.stackoverflow.com; expires=Fri, 01-Jan-2055 00:00:00 GMT; path=/; HttpOnly\r\n" \
      "Date: Sun, 02 Nov 2014 19:31:58 GMT\r\n\r\n"
      expect(subject.parse header).to eq([
        {:excluded=>"HTTP/1.1 200 OK"},
        {cache_control: "public, no-cache=\"Set-Cookie\", max-age=1"},
        {excluded: "Content-Length: 237857"},
        {excluded: "Content-Type: text/html; charset=utf-8"},
        {expires: "Sun, 02 Nov 2014 19:32:00 GMT"},
        {excluded: "Last-Modified: Sun, 02 Nov 2014 19:31:00 GMT"},
        {excluded: "Vary: *"},
        {:x_frame_options=>"SAMEORIGIN"},
        {excluded: "Set-Cookie: prov=23def875-91bc-4a7b-a255-15544b6389d8; domain=.stackoverflow.com; expires=Fri, 01-Jan-2055 00:00:00 GMT; path=/; HttpOnly"},
        {excluded: "Date: Sun, 02 Nov 2014 19:31:58 GMT"},
      ])
    end

  end

  describe "X-Frames-Options" do
    subject { described_class.new.security_headers }

    it "parses deny" do
      header = "X-Frame-Options: deny\r\n\r\n"
      expect(subject.parse header).to eq(
        {x_frame_options: "deny"}
      )
    end

    it "parses allow-from" do
      header = "X-Frame-Options: allow-from http://www.example.com\r\n\r\n"
      expect(subject.parse header).to eq(
        {x_frame_options: "allow-from http://www.example.com"}
      )
    end

    it "parses sameorigin" do
      header = "X-Frame-Options: sameorigin\r\n\r\n"
      expect(subject.parse header).to eq(
        {x_frame_options: "sameorigin"}
      )
    end
  end

  describe "Strict-Transport-Security" do
    subject { described_class.new.security_headers }

    it "accepts only max-age" do
      header = "Strict-Transport-Security: max-age=31536000\r\n\r\n"
      expect(subject.parse header).to eq(
        {strict_transport_security: "max-age=31536000"}
      )
    end

    it "accepts max-age of zero" do
      header = "Strict-Transport-Security: max-age=0\r\n\r\n"
      expect(subject.parse header).to eq(
        {strict_transport_security: "max-age=0"}
      )
    end

    it "accepts max-age then includeSubdomains" do
      header = "Strict-Transport-Security: max-age=0; includeSubDomains\r\n\r\n"
      expect(subject.parse header).to eq(
        {strict_transport_security: "max-age=0; includeSubDomains"}
      )
    end

    it "accepts includeSubdomains then max-age" do
      header = "Strict-Transport-Security: includeSubDomains; max-age=0\r\n\r\n"
      expect(subject.parse header).to eq(
        {strict_transport_security: "includeSubDomains; max-age=0"}
      )
    end
  end

  describe "X-Content-Type-Options" do
    subject { described_class.new.security_headers }

    it "accepts nosniff" do
      header = "X-Content-Type-Options: nosniff\r\n\r\n"
      expect(subject.parse header).to eq(
        { x_content_type_options: "nosniff"}
      )
    end
  end

  describe "X-XSS-Protection" do
    subject { described_class.new.security_headers }

    it "it accepts 1; mode=block" do
      header = "X-XSS-Protection: 1; mode=block\r\n\r\n"
      expect(subject.parse header).to eq(
        { x_xss_protection: "1; mode=block" }
      )
    end

    it "it accepts 0; mode=block" do
      header = "X-XSS-Protection: 0; mode=block\r\n\r\n"
      expect(subject.parse header).to eq(
        { x_xss_protection: "0; mode=block" }
      )
    end

    it "it accepts 1" do
      header = "X-XSS-Protection: 1\r\n\r\n"
      expect(subject.parse header).to eq(
        { x_xss_protection: "1" }
      )
    end
  end

  describe "Cache-Control" do
    subject { described_class.new.security_headers }

    it "it accepts private" do
      header = "Cache-Control: private\r\n\r\n"
      expect(subject.parse header).to eq(
        { cache_control: "private" }
      )
    end

    it "it accepts public, max-age=1" do
      header = "Cache-Control: public, max-age=1\r\n\r\n"
      expect(subject.parse header).to eq(
        { cache_control: "public, max-age=1" }
      )
    end

    it "it accepts all recommended value: private, max-age=0, no-cache" do
      header = "Cache-Control: private, max-age=0, no-cache\r\n\r\n"
      expect(subject.parse header).to eq(
        { cache_control: "private, max-age=0, no-cache" }
      )
    end
  end

  describe "Pragma" do
    subject { described_class.new.security_headers }

    it "accepts no-cache" do
      header = "pragma: no-cache\r\n\r\n"
      expect(subject.parse header).to eq(
        { pragma: "no-cache" }
      )
    end
  end

  describe "Expires" do
    subject { described_class.new.security_headers }

    it "parses rfc1123-date" do
      header = "Expires: Thu, 04 Dec 2015 16:00:00 GMT\r\n\r\n"
      expect(subject.parse header).to eq(
        { expires: "Thu, 04 Dec 2015 16:00:00 GMT" }
      )
    end

    it "parses rfc850-date" do
      header = "Expires: Thursday, 04-Dec-15 16:00:00 GMT\r\n\r\n"
      expect(subject.parse header).to eq(
        { expires: "Thursday, 04-Dec-15 16:00:00 GMT" }
      )
    end

    it "parses asctime-date format #1" do
      header = "Expires: Thu Dec 04 16:00:00 2015\r\n\r\n"
      expect(subject.parse header).to eq(
        { expires: "Thu Dec 04 16:00:00 2015" }
      )
    end

    it "parses asctime-date format #2" do
      header = "Expires: Thu Dec  4 16:00:00 2015\r\n\r\n"
      expect(subject.parse header).to eq(
        { expires: "Thu Dec  4 16:00:00 2015" }
      )
    end
  end

  describe "Expires" do
    subject { described_class.new.security_headers }

    it "parses rfc1123-date" do
      header = "Expires: Thu, 04 Dec 2015 16:00:00 GMT\r\n\r\n"
      expect(subject.parse header).to eq(
        { expires: "Thu, 04 Dec 2015 16:00:00 GMT" }
      )
    end

    it "parses rfc850-date" do
      header = "Expires: Thursday, 04-Dec-15 16:00:00 GMT\r\n\r\n"
      expect(subject.parse header).to eq(
        { expires: "Thursday, 04-Dec-15 16:00:00 GMT" }
      )
    end

    it "parses asctime-date format #1" do
      header = "Expires: Thu Dec 04 16:00:00 2015\r\n\r\n"
      expect(subject.parse header).to eq(
        { expires: "Thu Dec 04 16:00:00 2015" }
      )
    end

    it "parses asctime-date format #2" do
      header = "Expires: Thu Dec  4 16:00:00 2015\r\n\r\n"
      expect(subject.parse header).to eq(
        { expires: "Thu Dec  4 16:00:00 2015" }
      )
    end
  end

  describe "X-Permitted-Cross-Domain-Policies" do
    subject { described_class.new.security_headers }

    it "accepts none" do
      header = "X-Permitted-Cross-Domain-Policies: none\r\n\r\n"
      expect(subject.parse header).to eq(
        { x_permitted_cross_domain_policies: "none" }
      )
    end

    it "accepts master-only" do
      header = "X-Permitted-Cross-Domain-Policies: master-only\r\n\r\n"
      expect(subject.parse header).to eq(
        { x_permitted_cross_domain_policies: "master-only" }
      )
    end

    it "accepts by-content-type" do
      header = "X-Permitted-Cross-Domain-Policies: by-content-type\r\n\r\n"
      expect(subject.parse header).to eq(
        { x_permitted_cross_domain_policies: "by-content-type" }
      )
    end

    it "accepts by-ftp-filename" do
      header = "X-Permitted-Cross-Domain-Policies: by-ftp-filename\r\n\r\n"
      expect(subject.parse header).to eq(
        { x_permitted_cross_domain_policies: "by-ftp-filename" }
      )
    end

    it "accepts all" do
      header = "X-Permitted-Cross-Domain-Policies: all\r\n\r\n"
      expect(subject.parse header).to eq(
        { x_permitted_cross_domain_policies: "all" }
      )
    end
  end

  describe "Content-Security-Policy" do
    it "accepts default-src 'self'" do
      header = "Content-Security-Policy: default-src 'self';\r\n\r\n"
      expect(subject.parse header).to eq(
        { content_security_policy: "default-src 'self';" }
      )
    end

    it "accepts default-src 'self'; script-src 'self';" do
      header = "Content-Security-Policy: default-src 'self'; script-src 'self';\r\n\r\n"
      expect(subject.parse header).to eq(
        { content_security_policy: "default-src 'self'; script-src 'self';" }
      )
    end

    it "accepts a domain" do
      header = "Content-Security-Policy: default-src 'self' trustedscripts.foo.com\r\n\r\n"
      expect(subject.parse header).to eq(
        { content_security_policy: "default-src 'self' trustedscripts.foo.com" }
      )
    end

    it "accepts img-src and media-src" do
      header = "Content-Security-Policy: default-src 'self'; img-src 'self' data:; media-src mediastream:\r\n\r\n"
      expect(subject.parse header).to eq(
        { content_security_policy: "default-src 'self'; img-src 'self' data:; media-src mediastream:" }
      )
    end
  end

  context "Alexa Top 100", :gauntlet do
    require 'csv'

    path = File.expand_path('../data/alexa.csv', __FILE__)
    csv  = CSV.new(open(path), headers: false)

    csv.each do |row|
      rank, domain = row

      it "should parse #{domain}" do
        head = Curl::Easy.http_head("http://#{domain}")
        expect { subject.parse(head.header_str) }.to_not raise_error
      end
    end
  end

end
