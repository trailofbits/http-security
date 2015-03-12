require 'spec_helper'
require 'http/security/headers/cache_control'

describe HTTP::Security::Headers::CacheControl do
  let(:max_age) { 0 }

  subject do
    described_class.new(
      private: true,
      max_age: max_age,
      no_cache: true
    )
  end

  describe "#initialize" do
    it "should set max_age" do
      expect(subject.max_age).to be == max_age
    end
  end

  describe "#private?" do
    context "when private: is true" do
      subject { described_class.new(private: true) }

      it { expect(subject.private?).to be(true) }
    end

    context "when private: is false" do
      subject { described_class.new(private: false) }

      it { expect(subject.private?).to be(false) }
    end
  end

  describe "#to_s" do
    it "should return a comma separated list of directives" do
      expect(subject.to_s).to be == "private, max-age=#{max_age}, no-cache"
    end
  end
end
