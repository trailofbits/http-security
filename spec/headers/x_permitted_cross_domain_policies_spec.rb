require 'spec_helper'
require 'http/security/headers/x_permitted_cross_domain_policies'

require 'uri'

describe HTTP::Security::Headers::XPermittedCrossDomainPolicies do
  describe "#none?" do
    context "when none: was true" do
      subject { described_class.new(none: true) }

      it { expect(subject.none?).to be true }
    end

    context "when none: was false" do
      subject { described_class.new(none: false) }

      it { expect(subject.none?).to be false }
    end
  end

  describe "#master_only?" do
    context "when master_only: was true" do
      subject { described_class.new(master_only: true) }

      it { expect(subject.master_only?).to be true }
    end

    context "when master_only: was false" do
      subject { described_class.new(master_only: false) }

      it { expect(subject.master_only?).to be false }
    end
  end

  describe "#by_content_type?" do
    context "when by_content_type: was true" do
      subject { described_class.new(by_content_type: true) }

      it { expect(subject.by_content_type?).to be true }
    end

    context "when by_content_type: was false" do
      subject { described_class.new(by_content_type: false) }

      it { expect(subject.by_content_type?).to be false }
    end
  end

  describe "#by_ftp_filename?" do
    context "when by_ftp_filename: was true" do
      subject { described_class.new(by_ftp_filename: true) }

      it { expect(subject.by_ftp_filename?).to be true }
    end

    context "when by_ftp_filename: was false" do
      subject { described_class.new(by_ftp_filename: false) }

      it { expect(subject.by_ftp_filename?).to be false }
    end
  end

  describe "#all?" do
    context "when all: was true" do
      subject { described_class.new(all: true) }

      it { expect(subject.all?).to be true }
    end

    context "when all: was false" do
      subject { described_class.new(all: false) }

      it { expect(subject.all?).to be false }
    end
  end

  describe "#to_s" do
    context "when none: was true" do
      subject { described_class.new(none: true) }

      it { expect(subject.to_s).to be == 'none' }
    end

    context "when master_only: was true" do
      subject { described_class.new(master_only: true) }

      it { expect(subject.to_s).to be == 'master-only' }
    end

    context "when by_content_type: was true" do
      subject { described_class.new(by_content_type: true) }

      it { expect(subject.to_s).to be == 'by-content-type' }
    end

    context "when by_ftp_filename: was true" do
      subject { described_class.new(by_ftp_filename: true) }

      it { expect(subject.to_s).to be == 'by-ftp-filename' }
    end

    context "when all: was true" do
      subject { described_class.new(all: true) }

      it { expect(subject.to_s).to be == 'all' }
    end
  end
end
