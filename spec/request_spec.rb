require "spec_helper"
require "security_headers/request"
require 'curb'

describe Request do
  it "returns a an array of hashes for valid domains" do
    params = SecurityHeaders::Request.parse_headers("http://www.google.com")
    expect(params).to be_a_kind_of(Array)
    expect(params.first).to be_a_kind_of(Hash)
  end
end
