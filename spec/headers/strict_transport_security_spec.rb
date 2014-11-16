require "spec_helper"
require "security_headers/headers/strict_transport_security"

describe StrictTransportSecurity do
  describe "Strict-Transport-Security" do
    subject { described_class.new.strict_transport_security }

    it "accepts only max-age" do
      header = "Strict-Transport-Security: max-age=31536000"
      expect(subject.parse header).to eq(
        {strict_transport_security: "max-age=31536000"}
      )
    end

    it "accepts max-age of zero" do
      header = "Strict-Transport-Security: zaxzage=0; max-age=0"
      expect(subject.parse header).to eq(
        {strict_transport_security: "zaxzage=0; max-age=0"}
      )
    end

    it "accepts max-age then includeSubdomains" do
      header = "Strict-Transport-Security: max-age=0; includeSubDomains"
      expect(subject.parse header).to eq(
        {strict_transport_security: "max-age=0; includeSubDomains"}
      )
    end

    it "accepts includeSubdomains then max-age" do
      header = "Strict-Transport-Security: includeSubDomains; max-age=0"
      expect(subject.parse header).to eq(
        {strict_transport_security: "includeSubDomains; max-age=0"}
      )
    end
  end
end
