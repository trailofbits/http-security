require "spec_helper"
require "http/security/parsers/pragma"

describe Parsers::Pragma do
  it "accepts no-cache" do
    header = "no-cache"

    expect(subject.parse(header)).to be == {no_cache: true}
  end
end
