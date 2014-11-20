require "spec_helper"
require "security_headers/parsers/x_xss_protection"

describe Parsers::XXSSProtection do
  it "it accepts 1; mode=block" do
    header = "1; mode=block"

    expect(subject.parse(header)).to eq(
      "1; mode=block"
    )
  end

  it "it accepts 0; mode=block" do
    header = "0; mode=block"

    expect(subject.parse(header)).to eq(
      "0; mode=block"
    )
  end

  it "it accepts 1" do
    header = "1"

    expect(subject.parse(header)).to eq(
      "1"
    )
  end
end
