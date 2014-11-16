require "spec_helper"
require "security_headers/headers/x_xss_protection"

describe XXSSProtection do
  describe "X-XSS-Protection" do
    subject { described_class.new.x_xss_protection }

    it "it accepts 1; mode=block" do
      header = "X-XSS-Protection: 1; mode=block"
      expect(subject.parse header).to eq(
        { x_xss_protection: "1; mode=block" }
      )
    end

    it "it accepts 0; mode=block" do
      header = "X-XSS-Protection: 0; mode=block"
      expect(subject.parse header).to eq(
        { x_xss_protection: "0; mode=block" }
      )
    end

    it "it accepts 1" do
      header = "X-XSS-Protection: 1"
      expect(subject.parse header).to eq(
        { x_xss_protection: "1" }
      )
    end
  end
end
