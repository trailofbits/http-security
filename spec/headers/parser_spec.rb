require "spec_helper"
require 'security_headers/headers/base_parser'

describe BaseParser do

  describe "General date parsing" do
    subject { described_class.new.http_date }
    it "parses rfc1123-date" do
      date = "Thu, 04 Dec 2015 16:00:00 GMT"
      expect(subject.parse(date)).to eq(date)
    end
    it "parses rfc850-date" do
      date = "Thursday, 04-Dec-15 16:00:00 GMT"
      expect(subject.parse(date)).to eq(date)
    end
    it "parses rfc1123-date" do
      date = "Thu Dec 04 16:00:00 2015"
      expect(subject.parse(date)).to eq(date)
    end
  end

end
