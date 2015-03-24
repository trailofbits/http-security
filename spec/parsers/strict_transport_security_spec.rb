require "spec_helper"
require "http/security/parsers/strict_transport_security"

describe Parsers::StrictTransportSecurity do
  it "accepts only max-age" do
    header = "max-age=31536000"

    expect(subject.parse(header)).to be == {max_age: 31536000}
  end

  it "accepts max-age of zero" do
    header = "max-age=0"

    expect(subject.parse(header)).to eq(max_age: 0)
  end

  it "accepts max-age then includeSubDomains" do
    header = "max-age=0; includeSubDomains"

    expect(subject.parse(header)).to be == {
      max_age: 0,
      includesubdomains: true
    }
  end

  it "accepts includeSubDomains then max-age" do
    header = "includeSubDomains; max-age=0"

    expect(subject.parse(header)).to be == {
      includesubdomains: true,
      max_age: 0
    }
  end

  describe "stp_header_extension" do
    subject { super().stp_header_extension }

    it "accepts includedSubdomains" do
      expect(subject.parse('includeSubDomains')).to be == {
        key: "includeSubDomains"
      }
    end

    it "accepts an unsupported token" do
      expect(subject.parse("preload")).to be == {name: 'preload'}
    end

    it "accepts an unsupported token=token" do
      expect(subject.parse("foo=bar")).to be == {
        name:  'foo',
        value: 'bar'
      }
    end

    it "accepts token=\"string\"" do
      expect(subject.parse('foo="string"')).to be == {
        name: 'foo',
        value: {string: 'string'}
      }
    end
  end
end
