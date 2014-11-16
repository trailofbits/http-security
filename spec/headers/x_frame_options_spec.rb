require "spec_helper"
require "security_headers/headers/x_frame_options"

describe XFrameOptions do
  describe "X-Frame-Options" do
    subject { described_class.new.x_frame_options }

    it "parses deny" do
      header = "X-Frame-Options: deny"
      expect(subject.parse header).to eq(
        {x_frame_options: "deny"}
      )
    end

    it "parses allow-from" do
      header = "X-Frame-Options: allow-from http://www.example.com"
      expect(subject.parse header).to eq(
        {x_frame_options: "allow-from http://www.example.com"}
      )
    end

    it "parses sameorigin" do
      header = "X-Frame-Options: sameorigin"
      expect(subject.parse header).to eq(
        {x_frame_options: "sameorigin"}
      )
    end
  end
end
