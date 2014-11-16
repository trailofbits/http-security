require "spec_helper"
require "security_headers/headers/expires"

describe Expires do
  describe "Expires" do
    subject { described_class.new.expires }

    it "parses negative integers" do
      header = "Expires: -1"
      expect(subject.parse header).to eq(
        { expires: "-1" }
      )
    end

    it "parses 0" do
      header = "Expires: 0"
      expect(subject.parse header).to eq(
        { expires: "0" }
      )
    end

    it "parses positive integers" do
      header = "Expires: 100"
      expect(subject.parse header).to eq(
        { expires: "100" }
      )
    end


    it "parses rfc1123-date" do
      header = "Expires: Thu, 04 Dec 2015 16:00:00 GMT"
      expect(subject.parse header).to eq(
        { expires: "Thu, 04 Dec 2015 16:00:00 GMT" }
      )
    end

    it "parses rfc850-date" do
      header = "Expires: Thursday, 04-Dec-15 16:00:00 GMT"
      expect(subject.parse header).to eq(
        { expires: "Thursday, 04-Dec-15 16:00:00 GMT" }
      )
    end

    it "parses asctime-date format #1" do
      header = "Expires: Thu Dec 04 16:00:00 2015"
      expect(subject.parse header).to eq(
        { expires: "Thu Dec 04 16:00:00 2015" }
      )
    end

    it "parses asctime-date format #2" do
      header = "Expires: Thu Dec  4 16:00:00 2015"
      expect(subject.parse header).to eq(
        { expires: "Thu Dec  4 16:00:00 2015" }
      )
    end

    it "parses rfc1123-date" do
      header = "Expires: Thu, 04 Dec 2015 16:00:00 GMT"
      expect(subject.parse header).to eq(
        { expires: "Thu, 04 Dec 2015 16:00:00 GMT" }
      )
    end

    it "parses rfc850-date" do
      header = "Expires: Thursday, 04-Dec-15 16:00:00 GMT"
      expect(subject.parse header).to eq(
        { expires: "Thursday, 04-Dec-15 16:00:00 GMT" }
      )
    end

    it "parses asctime-date format #1" do
      header = "Expires: Thu Dec 04 16:00:00 2015"
      expect(subject.parse header).to eq(
        { expires: "Thu Dec 04 16:00:00 2015" }
      )
    end

    it "parses asctime-date format #2" do
      header = "Expires: Thu Dec  4 16:00:00 2015"
      expect(subject.parse header).to eq(
        { expires: "Thu Dec  4 16:00:00 2015" }
      )
    end
  end
end
