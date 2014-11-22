require "spec_helper"
require "http/security/parsers/x_permitted_cross_domain_policies"

describe Parsers::XPermittedCrossDomainPolicies do
  it "accepts none" do
    header = "none"

    expect(subject.parse(header)).to be == {none: true}
  end

  it "accepts master-only" do
    header = "master-only"

    expect(subject.parse(header)).to be == {master_only: true}
  end

  it "accepts by-content-type" do
    header = "by-content-type"

    expect(subject.parse(header)).to be == {by_content_type: true}
  end

  it "accepts by-ftp-filename" do
    header = "by-ftp-filename"

    expect(subject.parse(header)).to be == {by_ftp_filename: true}
  end

  it "accepts all" do
    header = "all"

    expect(subject.parse(header)).to be == {all: true}
  end
end
