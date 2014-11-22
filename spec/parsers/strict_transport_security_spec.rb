require "spec_helper"
require "http/security/parsers/strict_transport_security"

describe Parsers::StrictTransportSecurity do
  it "accepts only max-age" do
    header = "max-age=31536000"

    expect(subject.parse(header)).to be == {max_age: 31536000}
  end

  it "accepts max-age of zero" do
    header = "zaxzage=0; max-age=0"

    expect(subject.parse(header)).to eq(max_age: 0)
  end

  it "accepts max-age then includeSubdomains" do
    header = "max-age=0; includeSubDomains"

    expect(subject.parse(header)).to be == {
      max_age: 0,
      includesubdomains: true
    }
  end

  it "accepts includeSubdomains then max-age" do
    header = "includeSubDomains; max-age=0"

    expect(subject.parse(header)).to be == {
      includesubdomains: true,
      max_age: 0
    }
  end
end
