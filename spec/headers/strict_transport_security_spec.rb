require 'spec_helper'
require 'http/security/headers/strict_transport_security'

describe HTTP::Security::Headers::StrictTransportSecurity do
  let(:max_age) { 31536000 }

  subject do
    described_class.new(
      max_age:           max_age,
      includesubdomains: true
    )
  end

  describe "#initialize" do
    it "should set max_age" do
      expect(subject.max_age).to be == max_age
    end
  end

  describe "#include_sub_domains?" do
    context "when includesubdomains: was true" do
      subject { described_class.new(includesubdomains: true) }

      it { expect(subject.include_sub_domains?).to be true }
    end

    context "when includesubdomains: was false" do
      subject { described_class.new(includesubdomains: false) }

      it { expect(subject.include_sub_domains?).to be false }
    end
  end

  describe "#to_s" do
    it "should return a string" do
      expect(subject.to_s).to be == "max-age=#{max_age}; includeSubDomains"
    end
  end
end
