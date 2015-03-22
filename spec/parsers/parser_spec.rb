require "spec_helper"
require 'http/security/parsers/parser'

describe Parsers::Parser do
  describe "#http_date" do
    subject { super().http_date }

    it "parses rfc1123-date" do
      date = "Thu, 04 Dec 2015 16:00:00 GMT"

      expect(subject.parse(date)).to eq(date: date)
    end

    it "parses rfc850-date" do
      date = "Thursday, 04-Dec-15 16:00:00 GMT"

      expect(subject.parse(date)).to eq(date: date)
    end

    it "parses rfc1123-date" do
      date = "Thu Dec 04 16:00:00 2015"

      expect(subject.parse(date)).to eq(date: date)
    end
  end

  describe "#header_extension" do
    subject { super().header_extension }

    let(:name) { 'foo' }

    context "when parsing a token" do
      it "should tag the token name" do
        expect(subject.parse(name)).to eq(name: name)
      end
    end

    context "when parsing a token and a value" do
      let(:value) { 'bar' }

      it "should tag the token and value" do
        expect(subject.parse("#{name}=#{value}")).to eq(
          name: name,
          value: value
        )
      end
    end
  end

  describe "#uri" do
    let(:transform) { Parsers::Parser::Transform.new }
    subject { super().uri }

    it "parses a uri without a scheme specified" do
      uri = "www.example.com"
      expect(transform.apply(subject.parse(uri))).to eq(URI.parse(uri))
    end

    it "parses a uri with a scheme specified" do
      uri = "https://www.example.com"
      expect(transform.apply(subject.parse(uri))).to eq(URI.parse(uri))
    end

    it "parses a uri with a path specified" do
      uri = "http://www.example.com/about"
      expect(transform.apply(subject.parse(uri))).to eq(URI.parse(uri))
    end

    it "parses a uri with parameters" do
      uri = "http://www.example.com/about?parameter1=val1&parameter2=val2"
      expect(transform.apply(subject.parse(uri))).to eq(URI.parse(uri))
    end

    it "parses a uri with a redirect address in its parameters" do
      uri = "http://www.example.com/url?sa=X&q=http://example2.com/article/headline_20101013&ct=ga&cad=:n1:n2:t1286988171:&cd=yQ=AG-Tx"
      expect(transform.apply(subject.parse(uri))).to eq(URI.parse(uri))
    end

    it "parses a uri with fragments" do
      uri = "http://www.example.com/url#fragment"
      expect(transform.apply(subject.parse(uri))).to eq(URI.parse(uri))
    end

    it "parses an ftp uri" do
      uri = "ftp://ftp.is.co.za/rfc/rfc1808.txt"
      expect(transform.apply(subject.parse(uri))).to eq(URI.parse(uri))
    end

    it "parses a uri with a port" do
      uri = "telnet://192.0.2.16:80/"
      expect(transform.apply(subject.parse(uri))).to eq(URI.parse(uri))
    end
  end

end
