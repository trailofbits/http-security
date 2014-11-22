require "spec_helper"
require "security_headers/parsers/x_content_type_options"

describe Parsers::XContentTypeOptions do
  it "accepts nosniff" do
    header = "nosniff"

    expect(subject.parse(header)).to eq(nosniff: true)
  end
end
