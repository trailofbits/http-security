require "spec_helper"
require "http/security/parsers/content_security_policy_report_only"

describe Parsers::ContentSecurityPolicyReportOnly do
  it "accepts default-src 'self'" do
    header = "default-src 'self';"

    expect(subject.parse(header)).to eq(
      default_src: "'self'"
    )
  end

  it "accepts default-src 'self'; script-src 'self';" do
    header = "default-src 'self'; script-src 'self';"

    expect(subject.parse(header)).to eq(
      default_src: "'self'",
      script_src: "'self'"
    )
  end

  it "accepts a domain" do
    header = "default-src 'self' trustedscripts.foo.com"

    expect(subject.parse(header)).to eq(
      default_src: "'self' trustedscripts.foo.com"
    )
  end

  it "accepts img-src and media-src" do
    header = "default-src 'self'; img-src 'self' data:; media-src mediastream:"

    expect(subject.parse(header)).to eq(
      default_src: "'self'",
      img_src: "'self' data:",
      media_src: "mediastream:"
    )
  end
end
