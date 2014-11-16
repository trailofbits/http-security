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

  describe "General date parsing" do
    subject { described_class.new.http_date }
    it "parses rfc1123-date" do
      date = "Thu, 04 Dec 2015 16:00:00 GMT"
      expect(subject.parse(date)).to eq(date)
    end
    it "parses rfc850-date" do
      date = "Thursday, 04-Dec-15 16:00:00 GMT"
      expect(subject.parse(date)).to eq(date)
    end
    it "parses rfc1123-date" do
      date = "Thu Dec 04 16:00:00 2015"
      expect(subject.parse(date)).to eq(date)
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
