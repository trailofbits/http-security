require "spec_helper"
require "security_headers/parsers/cache_control"

describe Parsers::CacheControl do
  it "accepts private" do
    header = 'private'

    expect(subject.parse(header)).to be == {private: true}
  end

  it "accepts public, max-age=1" do
    header = "public, max-age=1"

    expect(subject.parse(header)).to be == {public: true, max_age: 1}
  end

  it "accepts all recommended value: private, max-age=0, no-cache" do
    header = "private, max-age=0, no-cache"

    expect(subject.parse(header)).to be == {
      private: true,
      max_age: 0,
      no_cache: true
    }
  end
end
