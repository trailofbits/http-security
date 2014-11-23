require "spec_helper"
require "http/security/parsers/content_security_policy"
require "pry"

describe Parsers::ContentSecurityPolicy do
  it "accepts default-src 'self'" do
    header = "default-src 'self';"

    expect(subject.parse(header)).to be == {
      default_src: "'self'"
    }
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

 it "accepts wildcard domains" do
  header = "default-src 'self'; img-src *; object-src media1.example.com media2.example.com *.cdn.example.com; script-src trustedscripts.example.com"

    expect(subject.parse(header)).to eq(
      default_src: "'self'",
      img_src: "*",
      object_src: "media1.example.com media2.example.com *.cdn.example.com",
      script_src: "trustedscripts.example.com"
    )
 end

 it "parses unsafe-inline and unsafe-eval", :focus => true do
  header = "default-src https: 'unsafe-inline' 'unsafe-eval'"
  response = subject.parse(header)

    expect(subject.parse(header)).to eq(
      default_src: "https: 'unsafe-inline' 'unsafe-eval'"
    )
 end

 describe "specific URI paths" do
  header = "default-src default-src 'self'; script-src https://example.com/js/"
    it "is not inlcuded in CSP 1.0. Enable ext_host_source to parse specific paths."
 end

end
