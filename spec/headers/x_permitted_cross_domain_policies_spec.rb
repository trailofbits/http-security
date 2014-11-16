require "spec_helper"
require "security_headers/headers/x_permitted_cross_domain_policies"

describe XPermitedCrossDomainPolicies do
  describe "X-Permitted-Cross-Domain-Policies" do
    subject { described_class.new.x_permitted_cross_domain_policies }

    it "accepts none" do
      header = "X-Permitted-Cross-Domain-Policies: none"
      expect(subject.parse header).to eq(
        { x_permitted_cross_domain_policies: "none" }
      )
    end

    it "accepts master-only" do
      header = "X-Permitted-Cross-Domain-Policies: master-only"
      expect(subject.parse header).to eq(
        { x_permitted_cross_domain_policies: "master-only" }
      )
    end

    it "accepts by-content-type" do
      header = "X-Permitted-Cross-Domain-Policies: by-content-type"
      expect(subject.parse header).to eq(
        { x_permitted_cross_domain_policies: "by-content-type" }
      )
    end

    it "accepts by-ftp-filename" do
      header = "X-Permitted-Cross-Domain-Policies: by-ftp-filename"
      expect(subject.parse header).to eq(
        { x_permitted_cross_domain_policies: "by-ftp-filename" }
      )
    end

    it "accepts all" do
      header = "X-Permitted-Cross-Domain-Policies: all"
      expect(subject.parse header).to eq(
        { x_permitted_cross_domain_policies: "all" }
      )
    end
  end
end
