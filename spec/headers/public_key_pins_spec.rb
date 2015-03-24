require 'spec_helper'
require 'http/security/headers/public_key_pins'

require 'uri'

describe HTTP::Security::Headers::PublicKeyPins do
  let(:pin_sha256) do
    [
      'klO23nT2ehFDXCfx3eHTDRESMz3asj1muO+4aIdjiuY=',
      'M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE='
    ]
  end
  let(:pin_sha9000)         { 'jlkfsjlksjlkfsjfs' }
  let(:max_age)             { 31536000 }
  let(:include_sub_domains) { true }
  let(:report_uri)          { URI('https://www.example.com/') }
  let(:strict)              { true }

  subject do
    described_class.new(
      pin_sha256:          pin_sha256,
      'pin-sha9000' =>     pin_sha9000,
      max_age:             max_age,
      includesubdomains:   include_sub_domains,
      report_uri:          report_uri,
      strict:              strict
    )
  end

  describe "#initialize" do
    it "should group together pin options" do
      expect(subject.pin).to be == {
        sha256:      pin_sha256,
        'sha9000' => [pin_sha9000]
      }
    end

    it "should set max_age" do
      expect(subject.max_age).to be max_age
    end

    it "should set include_sub_domains" do
      expect(subject.include_sub_domains?).to be include_sub_domains
    end

    it "should set report_uri" do
      expect(subject.report_uri).to be report_uri
    end

    it "should set strict" do
      expect(subject.strict?).to be strict
    end
  end

  describe "#to_s" do
    it "should return a semicolon separated list of directives" do
      expect(subject.to_s).to be == [
        "pin-sha256=\"#{pin_sha256[0]}\"",
        "pin-sha256=\"#{pin_sha256[1]}\"",
        "pin-sha9000=\"#{pin_sha9000}\"",
        "max-age=#{max_age}",
        "includeSubdomains",
        "report-uri=\"#{report_uri}\"",
        "strict"
      ].join('; ')
    end
  end
end
