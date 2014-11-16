require "spec_helper"
require "security_headers/headers/content_security_policy_report_only"

describe ContentSecurityPolicyReportOnly do
  describe "Content-Security-Policy-Report-Only" do
    subject { described_class.new.content_security_policy_report_only }

    it "accepts default-src 'self'" do
      header = "Content-Security-Policy-Report-Only: default-src 'self';"
      expect(subject.parse header).to eq(
        { content_security_policy_report_only: "default-src 'self';" }
      )
    end

    it "accepts default-src 'self'; script-src 'self';" do
      header = "Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self';"
      expect(subject.parse header).to eq(
        { content_security_policy_report_only: "default-src 'self'; script-src 'self';" }
      )
    end

    it "accepts a domain" do
      header = "Content-Security-Policy-Report-Only: default-src 'self' trustedscripts.foo.com"
      expect(subject.parse header).to eq(
        { content_security_policy_report_only: "default-src 'self' trustedscripts.foo.com" }
      )
    end

    it "accepts img-src and media-src" do
      header = "Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; media-src mediastream:"
      expect(subject.parse header).to eq(
        { content_security_policy_report_only: "default-src 'self'; img-src 'self' data:; media-src mediastream:" }
      )
    end
  end
end
