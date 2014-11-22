require "spec_helper"
require 'http/security/parsers/parser'

describe Parsers::Parser do
  describe "#http_date" do
    subject { super().http_date }

    it "parses rfc1123-date" do
      date = "Thu, 04 Dec 2015 16:00:00 GMT"

      expect(subject.parse(date)).to eq(date: date)
    end

    it "parses rfc850-date" do
      date = "Thursday, 04-Dec-15 16:00:00 GMT"

      expect(subject.parse(date)).to eq(date: date)
    end

    it "parses rfc1123-date" do
      date = "Thu Dec 04 16:00:00 2015"

      expect(subject.parse(date)).to eq(date: date)
    end
  end
end
