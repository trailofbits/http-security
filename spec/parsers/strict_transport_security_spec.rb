require "spec_helper"
require "security_headers/parsers/strict_transport_security"

describe Parsers::StrictTransportSecurity do
  it "accepts only max-age" do
    header = "max-age=31536000"

    expect(subject.parse(header)).to eq(
      "max-age=31536000"
    )
  end

  it "accepts max-age of zero" do
    header = "zaxzage=0; max-age=0"

    expect(subject.parse(header)).to eq(
      "zaxzage=0; max-age=0"
    )
  end

  it "accepts max-age then includeSubdomains" do
    header = "max-age=0; includeSubDomains"

    expect(subject.parse(header)).to eq(
      "max-age=0; includeSubDomains"
    )
  end

  it "accepts includeSubdomains then max-age" do
    header = "includeSubDomains; max-age=0"

    expect(subject.parse(header)).to eq(
      "includeSubDomains; max-age=0"
    )
  end
end
