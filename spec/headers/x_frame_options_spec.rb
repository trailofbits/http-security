require 'spec_helper'
require 'http/security/headers/x_frame_options'

require 'uri'

describe HTTP::Security::Headers::XFrameOptions do
  let(:allow_from) { URI('http://example.com/') }

  subject { described_class.new(allow_from: allow_from) }

  describe "#initialize" do
    context "when allow_from: is passed" do
      it "should set allow_from" do
        expect(subject.allow_from).to be allow_from
      end
    end
  end

  describe "deny?" do
    context "when deny: was true" do
      subject { described_class.new(deny: true) }

      it { expect(subject.deny?).to be true }
    end

    context "when deny: was false" do
      subject { described_class.new(deny: false) }

      it { expect(subject.deny?).to be false }
    end
  end

  describe "same_origin?" do
    context "when sameorigin: was true" do
      subject { described_class.new(sameorigin: true) }

      it { expect(subject.same_origin?).to be true }
    end

    context "when sameorigin: was false" do
      subject { described_class.new(sameorigin: false) }

      it { expect(subject.same_origin?).to be false }
    end
  end

  describe "allow_all?" do
    context "when allowall: was true" do
      subject { described_class.new(allowall: true) }

      it { expect(subject.allow_all?).to be true }
    end

    context "when sameorigin: was false" do
      subject { described_class.new(allowall: false) }

      it { expect(subject.allow_all?).to be false }
    end
  end

  describe "#to_s" do
    context "when deny: was true" do
      subject { described_class.new(deny: true) }

      it { expect(subject.to_s).to be == 'DENY' }
    end

    context "when same_origin: was true" do
      subject { described_class.new(sameorigin: true) }

      it { expect(subject.to_s).to be == 'SAMEORIGIN' }
    end

    context "when allow_from: was specified" do
      subject { described_class.new(allow_from: allow_from) }

      it { expect(subject.to_s).to be == "ALLOW-FROM #{allow_from}" }
    end

    context "when allowall: was specified" do
      subject { described_class.new(allowall: allow_from) }

      it { expect(subject.to_s).to be == 'ALLOWALL' }
    end
  end
end
