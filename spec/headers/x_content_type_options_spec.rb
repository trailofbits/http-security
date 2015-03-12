require 'spec_helper'
require 'http/security/headers/x_content_type_options'

describe HTTP::Security::Headers::XContentTypeOptions do
  subject { described_class.new(nosniff: true) }

  describe "no_sniff?" do
    context "when nosniff: was true" do
      subject { described_class.new(nosniff: true) }

      it { expect(subject.no_sniff?).to be true }
    end

    context "when nosniff: was false" do
      subject { described_class.new(nosniff: false) }

      it { expect(subject.no_sniff?).to be false }
    end
  end

  describe "#to_s" do
    it "should return a string" do
      expect(subject.to_s).to be == "nosniff"
    end
  end
end
