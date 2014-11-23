require "spec_helper"
require "http/security/parsers/content_security_policy"

describe Parsers::ContentSecurityPolicy do
  it "accepts default-src 'self'" do
    header = "default-src 'self';"

    expect(subject.parse(header)).to eq(
      header
    )
  end

  it "accepts default-src 'self'; script-src 'self';" do
    header = "default-src 'self'; script-src 'self';"

    expect(subject.parse(header)).to eq(
      header
    )
  end

  it "accepts a domain" do
    header = "default-src 'self' trustedscripts.foo.com"

    expect(subject.parse(header)).to eq(
      header
    )
  end

  it "accepts img-src and media-src" do
    header = "default-src 'self'; img-src 'self' data:; media-src mediastream:"

    expect(subject.parse(header)).to eq(
      header
    )
  end

 it "accepts wildcard domains" do
  header = "default-src 'self'; img-src *; object-src media1.example.com media2.example.com *.cdn.example.com; script-src trustedscripts.example.com"

    expect(subject.parse(header)).to eq(
      header
    )
 end

 it "unsafe-inline and unsafe-eval" do
  header = "default-src https: 'unsafe-inline' 'unsafe-eval'"

    expect(subject.parse(header)).to eq(
      header
    )
 end

 it "specific paths" do
  header = "default-src http://example.com"

    expect(subject.parse(header)).to eq(
      header
    )
 end

end
