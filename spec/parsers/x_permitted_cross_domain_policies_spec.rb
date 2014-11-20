require "spec_helper"
require "security_headers/parsers/x_permitted_cross_domain_policies"

describe Parsers::XPermittedCrossDomainPolicies do
  it "accepts none" do
    header = "none"

    expect(subject.parse(header)).to eq(
      "none"
    )
  end

  it "accepts master-only" do
    header = "master-only"

    expect(subject.parse(header)).to eq(
      "master-only"
    )
  end

  it "accepts by-content-type" do
    header = "by-content-type"

    expect(subject.parse(header)).to eq(
      "by-content-type"
    )
  end

  it "accepts by-ftp-filename" do
    header = "by-ftp-filename"

    expect(subject.parse(header)).to eq(
      "by-ftp-filename"
    )
  end

  it "accepts all" do
    header = "all"

    expect(subject.parse(header)).to eq(
      "all"
    )
  end
end
