require 'spec_helper'
require 'http/security/headers/pragma'

describe HTTP::Security::Headers::Pragma do
  subject { described_class.new(no_cache: true) }

  describe "no_cache?" do
    context "when no_cache: was true" do
      subject { described_class.new(no_cache: true) }

      it { expect(subject.no_cache?).to be true }
    end

    context "when no_cache: was false" do
      subject { described_class.new(no_cache: false) }

      it { expect(subject.no_cache?).to be false }
    end
  end

  describe "#to_s" do
    it "should return a string" do
      expect(subject.to_s).to be == "no-cache"
    end
  end
end
