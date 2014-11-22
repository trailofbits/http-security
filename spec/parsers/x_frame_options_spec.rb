require "spec_helper"
require "http/security/parsers/x_frame_options"

describe Parsers::XFrameOptions do
  it "parses deny" do
    header = "deny"

    expect(subject.parse(header)).to be == {deny: true}
  end

  it "parses allow-from" do
    header = "allow-from http://www.example.com"

    expect(subject.parse(header)).to be == {
      allow_from: URI("http://www.example.com")
    }
  end

  it "parses sameorigin" do
    header = "sameorigin"

    expect(subject.parse(header)).to be == {sameorigin: true}
  end
end
