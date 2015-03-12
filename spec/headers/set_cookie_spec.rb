require 'spec_helper'
require 'http/security/headers/set_cookie'

require 'date'

describe HTTP::Security::Headers::SetCookie do
  let(:path)      { '/accounts' }
  let(:expires)   { Date.parse("Wed, 09 Jun 2021 10:18:14 GMT") }
  let(:secure)    { 'Secure' }
  let(:domain)    { '.example.com' }
  let(:http_only) { 'HttpOnly' }

  describe described_class::Cookie do
    let(:name)      { :foo  }
    let(:value)     { 'bar' }

    subject do
      described_class.new(
        cookie:    {name => value},
        path:      path,
        expires:   expires,
        secure:    secure,
        domain:    domain,
        http_only: http_only
      )
    end

    describe "#initialize" do
      it "should set cookie" do
        expect(subject.cookie).to be == {name => value}
      end
    end

    describe "#name" do
      it "should return the name" do
        expect(subject.name).to be == name
      end
    end

    describe "#value" do
      it "should return the value" do
        expect(subject.value).to be == value
      end
    end

    describe "#secure?" do
      context "when secure: was present" do
        subject { described_class.new(secure: 'Secure') }

        it { expect(subject.secure?).to be true}
      end

      context "when secure: was not present" do
        subject { described_class.new() }

        it { expect(subject.secure?).to be false }
      end
    end

    describe "#http_only?" do
      context "when http_only: was present" do
        subject { described_class.new(http_only: 'HttpOnly') }

        it { expect(subject.http_only?).to be true}
      end

      context "when http_only: was not present" do
        subject { described_class.new() }

        it { expect(subject.http_only?).to be false }
      end
    end

    describe "#to_s" do
      it "should format the cookie" do
        expect(subject.to_s).to be == "#{name}=#{value}; Path=#{path}; Domain=#{domain}; Expires=#{expires.httpdate}; #{secure}; #{http_only}"
      end
    end
  end

  let(:cookies) do
    [
      {
        cookie:    {foo: 'bar'},
        path:      path,
        domain:    domain,
        secure:    secure,
        http_only: http_only
      },

      {
        cookie:  {bar: 'baz'},
        domain:  domain,
        path:    path,
        expires: expires
      }
    ]
  end

  subject { described_class.new(cookies) }

  describe "#initialize" do
    it "should set cookies" do
      expect(subject.cookies.length).to be == cookies.length
      expect(subject.cookies).to all(be_kind_of(described_class::Cookie))
    end
  end

  describe "#each" do
    it "should enumerate over each cookie" do
      expect { |b|
        subject.each(&b)
      }.to yield_successive_args(*subject.cookies)
    end
  end

  describe "#to_s" do
    it "should return a semicolon separated list of directives" do
      expect(subject.to_s).to be == "foo=bar; Path=#{path}; Domain=#{domain}; Secure; HttpOnly, bar=baz; Path=#{path}; Domain=#{domain}; Expires=#{expires.httpdate}"
    end
  end
end
