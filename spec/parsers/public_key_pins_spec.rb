require 'spec_helper'
require 'http/security/parsers/public_key_pins'

describe Parsers::PublicKeyPins do
  let(:pin_sha256) { 'klO23nT2ehFDXCfx3eHTDRESMz3asj1muO+4aIdjiuY=' }
  let(:header)     { "pin-sha256=\"#{pin_sha256}\"" }

  it "parses the one pin-sha256=..." do
    expect(subject.parse(header)).to be == {pin_sha256: pin_sha256}
  end

  context "when given multiple pin-sha256= directives" do
    let(:primary)   { pin_sha256 }
    let(:secondary) { 'M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE=' }
    let(:header)    { "pin-sha256=\"#{primary}\"; pin-sha256=\"#{secondary}\"" }

    it "parses the pin-sha256=... directives into an Array" do
      expect(subject.parse(header)).to be == {pin_sha256: [primary, secondary]}
    end
  end

  context "when given pin- directives with unsupported hash algorithms" do
    let(:pin_sha9000) { "foo" }
    let(:header)      { "#{super()}; pin-sha9000=\"#{pin_sha9000}\"" }

    it "parses the unsupported pin- directives" do
      expect(subject.parse(header)).to be == {
        pin_sha256:  pin_sha256,
        pin_sha9000: pin_sha9000
      }
    end
  end

  context "when the max-age= directive is present" do
    let(:max_age) { 31536000 }
    let(:header)  { "pin-sha256=\"#{pin_sha256}\"; max-age=#{max_age}" }

    it "accepts pin-sha256=...; max-age=..." do
      expect(subject.parse(header)).to be == {
        pin_sha256: pin_sha256,
        max_age:    max_age
      }
    end

    context "when the includeSubdomains directive is present" do
      let(:header) { "#{super()}; includeSubdomains" }

      it "accepts pin-sha256=...; max-age=...; includeSubdomains" do
        expect(subject.parse(header)).to be == {
          pin_sha256:        pin_sha256,
          max_age:           max_age,
          includesubdomains: true
        }
      end
    end

    context "when the report-uri directive is present" do
      let(:report_uri) { URI('https://www.example.com/') }
      let(:header)     { "#{super()}; report-uri=\"#{report_uri}\"" }

      it "accepts pin-sha256=...; max-age=...; includeSubdomains" do
        expect(subject.parse(header)).to be == {
          pin_sha256: pin_sha256,
          max_age:    max_age,
          report_uri: report_uri
        }
      end
    end
  end

  context "when the strict directive is present" do
    let(:header) { "#{super()}; strict" }

    it "accepts pin-sha256=...; strict" do
      expect(subject.parse(header)).to be == {
        pin_sha256: pin_sha256,
        strict:     true
      }
    end
  end
end
