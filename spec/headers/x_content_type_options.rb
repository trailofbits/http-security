require "spec_helper"
require "security_headers/headers/x_content_type_options"

describe XContentTypeOptions do
  describe "X-Content-Type-Options" do
    subject { described_class.new.x_content_type_options }

    it "accepts nosniff" do
      header = "X-Content-Type-Options: nosniff"
      expect(subject.parse header).to eq(
        { x_content_type_options: "nosniff"}
      )
    end
  end
end







