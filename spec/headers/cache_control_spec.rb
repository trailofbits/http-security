require "spec_helper"
require "security_headers/headers/cache_control"

describe CacheControl do

  describe "Cache-Control" do
    subject { described_class.new.cache_control }

    it "it accepts private" do
      header = "Cache-Control: private"
      expect(subject.parse header).to eq(
        { cache_control: "private" }
      )
    end

    it "it accepts public, max-age=1" do
      header = "Cache-Control: public, max-age=1"
      expect(subject.parse header).to eq(
        { cache_control: "public, max-age=1" }
      )
    end

    it "it accepts all recommended value: private, max-age=0, no-cache" do
      header = "Cache-Control: private, max-age=0, no-cache"
      expect(subject.parse header).to eq(
        { cache_control: "private, max-age=0, no-cache" }
      )
    end
  end

end
