require "spec_helper"
require "security_headers/parsers/cache_control"

describe Parsers::CacheControl do
  it "accepts private" do
    header = 'private'

    expect(subject.parse(header)).to eq('private')
  end

  it "accepts public, max-age=1" do
    header = "public, max-age=1"

    expect(subject.parse(header)).to eq('public, max-age=1')
  end

  it "accepts all recommended value: private, max-age=0, no-cache" do
    header = "private, max-age=0, no-cache"

    expect(subject.parse(header)).to eq('private, max-age=0, no-cache')
  end
end
