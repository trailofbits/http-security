require 'spec_helper'
require 'http/security/malformed_header'

describe HTTP::Security::MalformedHeader do
  let(:value) { 'Foo, Bar; Baz' }
  let(:cause) { double(:cause) }

  subject { described_class.new(value,cause) }

  describe "#initialize" do
    it "should set #value" do
      expect(subject.value).to be(value)
    end

    it "should set #cause" do
      expect(subject.cause).to be(cause)
    end
  end

  describe "#to_s" do
    it "should return #value" do
      expect(subject.to_s).to be == subject.value
    end
  end
end
