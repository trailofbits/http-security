require "spec_helper"
require "security_headers/headers/pragma"

describe Pragma do
  describe "Pragma" do
    subject { described_class.new.pragma }

    it "accepts no-cache" do
      header = "pragma: no-cache"
      expect(subject.parse header).to eq(
        { pragma: "no-cache" }
      )
    end
  end
end
