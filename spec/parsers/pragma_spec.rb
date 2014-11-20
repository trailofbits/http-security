require "spec_helper"
require "security_headers/parsers/pragma"

describe Parsers::Pragma do
  it "accepts no-cache" do
    header = "no-cache"

    expect(subject.parse(header)).to eq(
      "no-cache"
    )
  end
end
