require 'spec_helper'
require 'http/security/headers/content_security_policy'

describe HTTP::Security::Headers::ContentSecurityPolicy do
  let(:default_src) { "'self'" }
  let(:img_src)   { '*' }
  let(:object_src)  { 'media1.example.com media2.example.com *.cdn.example.com' }
  let(:script_src)  { 'trustedscripts.example.com' }

  subject do
    described_class.new(
      default_src: default_src,
      img_src:     img_src,
      object_src:  object_src,
      script_src:  script_src
    )
  end

  describe "#initialize" do
    it "should set default_src"
    it "should set script_src"
    it "should set object_src"
    it "should set style_src"
    it "should set img_src"
    it "should set media_src"
    it "should set frame_src"
    it "should set font_src"
    it "should set connect_src"

    context "when report_uri: is omitted" do
      subject { described_class.new() }

      it "should default it to []" do
        expect(subject.report_uri).to be == []
      end
    end

    it "should set sandbox"
  end

  describe "#to_s" do
    it "should return a semicolon separated list of directives" do
      expect(subject.to_s).to be == "default-src #{default_src}; script-src #{script_src}; object-src #{object_src}; img-src #{img_src}"
    end
  end
end
