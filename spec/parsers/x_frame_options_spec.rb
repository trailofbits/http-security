require "spec_helper"
require "security_headers/parsers/x_frame_options"

describe Parsers::XFrameOptions do
  it "parses deny" do
    header = "deny"

    expect(subject.parse(header)).to eq(
      "deny"
    )
  end

  it "parses allow-from" do
    header = "allow-from http://www.example.com"

    expect(subject.parse(header)).to eq(
      "allow-from http://www.example.com"
    )
  end

  it "parses sameorigin" do
    header = "sameorigin"

    expect(subject.parse(header)).to eq(
      "sameorigin"
    )
  end
end
