require 'spec_helper'
require 'http/security/headers/x_xss_protection'

describe HTTP::Security::Headers::XXSSProtection do
  let(:mode) { 'block' }
  let(:report_uri) do
    "/xss-report/25b8988e-64ff-45a8-b0c6-2700fc1e9abd?source%5Baction%5D=index&source%5Bcontroller%5D=shop&source%5Bsection%5D=storefront"
  end

  subject do
    described_class.new(
      enabled: true,
      mode:    mode,
      report:  report_uri
    )
  end

  describe "#initialize" do
    it "should set mode" do
      expect(subject.mode).to be mode
    end

    it "should set report" do
      expect(subject.report).to be report_uri
    end
  end

  describe "#enabled?" do
    context "when enabled: was true" do
      subject { described_class.new(enabled: true) }

      it { expect(subject.enabled?).to be true }
    end

    context "when enabled: was false" do
      subject { described_class.new(enabled: false) }

      it { expect(subject.enabled?).to be false }
    end
  end

  describe "#to_s" do
    it "should return a string" do
      expect(subject.to_s).to be == "1; mode=#{mode}; report=#{report_uri}"
    end

    context "when enabled: was true" do
      subject { described_class.new(enabled: true) }

      it { expect(subject.to_s).to be == '1' }
    end

    context "when enabled: was false" do
      subject { described_class.new(enabled: false) }

      it { expect(subject.to_s).to be == '0' }
    end
  end
end
