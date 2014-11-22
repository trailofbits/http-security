require "spec_helper"
require "security_headers/parsers/pragma"

describe Parsers::Pragma do
  it "accepts no-cache" do
    header = "no-cache"

    expect(subject.parse(header)).to be == {no_cache: true}
  end
end
