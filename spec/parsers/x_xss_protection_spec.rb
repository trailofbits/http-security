require "spec_helper"
require "http/security/parsers/x_xss_protection"

describe Parsers::XXSSProtection do
  it "it accepts 1" do
    header = "1"

    expect(subject.parse(header)).to eq(enabled: true)
  end

  it "it accepts 0" do
    header = "0"

    expect(subject.parse(header)).to eq(enabled: false)
  end

  it "it accepts 1; mode=block" do
    header = "1; mode=block"

    expect(subject.parse(header)).to eq(enabled: true, mode: 'block')
  end

  it "it accepts 0; mode=block" do
    header = "0; mode=block"

    expect(subject.parse(header)).to eq(enabled: false, mode: 'block')
  end

  it "it accepts 1; mode=block; report=..." do
    report_uri = "/xss-report/25b8988e-64ff-45a8-b0c6-2700fc1e9abd?source%5Baction%5D=index&source%5Bcontroller%5D=shop&source%5Bsection%5D=storefront"
    header     = "1; mode=block; report=#{report_uri}"

    expect(subject.parse(header)).to eq(
      enabled: true,
      mode: 'block',
      report: report_uri
    )
  end
end
