require "spec_helper"
require "http/security/parsers/expires"

describe Parsers::Expires do
  it "parses negative integers" do
    header = "-1"

    expect(subject.parse(header)).to eq(-1)
  end

  it "parses 0" do
    header = "0"

    expect(subject.parse(header)).to eq(0)
  end

  it "parses positive integers" do
    header = "100"

    expect(subject.parse(header)).to eq(100)
  end

  it "parses rfc1123-date" do
    header = "Thu, 04 Dec 2015 16:00:00 GMT"
    date = Date.parse(header)

    expect(subject.parse(header)).to be == Date.parse(header)
  end

  it "parses rfc850-date" do
    header = "Thursday, 04-Dec-15 16:00:00 GMT"

    expect(subject.parse(header)).to be == Date.parse(header)
  end

  it "parses asctime-date format #1" do
    header = "Thu Dec 04 16:00:00 2015"

    expect(subject.parse(header)).to be == Date.parse(header)
  end

  it "parses asctime-date format #2" do
    header = "Thu Dec  4 16:00:00 2015"

    expect(subject.parse(header)).to be == Date.parse(header)
  end

  it "parses rfc1123-date" do
    header = "Thu, 04 Dec 2015 16:00:00 GMT"

    expect(subject.parse(header)).to be == Date.parse(header)
  end

  it "parses rfc850-date" do
    header = "Thursday, 04-Dec-15 16:00:00 GMT"

    expect(subject.parse(header)).to be == Date.parse(header)
  end

  it "parses asctime-date format #1" do
    header = "Thu Dec 04 16:00:00 2015"

    expect(subject.parse(header)).to be == Date.parse(header)
  end

  it "parses asctime-date format #2" do
    header = "Thu Dec  4 16:00:00 2015"

    expect(subject.parse(header)).to be == Date.parse(header)
  end
end
