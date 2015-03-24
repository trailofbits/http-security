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

  describe described_class::Transform do
    describe "boolean" do
      it "should map '0' to false" do
        expect(subject.apply({boolean: '0'})).to be false
      end

      it "should map 'no' to false" do
        expect(subject.apply({boolean: 'no'})).to be false
      end

      it "should map 'false' to false" do
        expect(subject.apply({boolean: 'false'})).to be false
      end

      it "should map '1' to true" do
        expect(subject.apply({boolean: '1'})).to be true
      end

      it "should map 'yes' to true" do
        expect(subject.apply({boolean: 'yes'})).to be true
      end

      it "should map 'true' to false" do
        expect(subject.apply({boolean: 'true'})).to be true
      end
    end

    describe "numeric" do
      it "should coerce Strings to Integer values" do
        expect(subject.apply({numeric: '42'})).to be 42
      end
    end

    describe "escaped_char" do
      context "when the escaped char is a control character" do
        let(:char) { 'n' }

        it "should map it to the control character" do
          expect(subject.apply({escaped_char: 'n'})).to be == "\n"
        end
      end

      context "when the escaped char is a printable character" do
        let(:char) { 'x' }

        it "should return the printable character" do
          expect(subject.apply({escaped_char: char})).to be == char
        end
      end
    end

    describe "string" do
      context "when given one String" do
        let(:string) { "foo bar" }

        it "should return the String" do
          expect(subject.apply({string: string})).to be == string
        end
      end

      context "when given multiple Strings" do
        let(:strings) { ['foo', "\n", 'bar'] }

        it "should join the Strings" do
          expect(subject.apply({string: strings})).to be == strings.join
        end
      end
    end

    describe "date" do
      let(:string) { 'Tue, 24 Mar 2015 00:00:00 GMT' }
      let(:date)   { Date.parse(string) }

      it "should return an HTTPDate" do
        expect(subject.apply({date: string})).to be_kind_of(HTTPDate)
      end

      it "should coerce Strings to Date values" do
        expect(subject.apply({date: string})).to be == date
      end
    end

    describe "uri" do
      let(:string) { 'https://www.example.com/?foo=bar' }
      let(:uri)    { URI(string) }

      it "should parse Strings as URIs" do
        expect(subject.apply({uri: string})).to be == uri
      end
    end

    describe "list" do
      context "when given a single element" do
        let(:element) { 'foo' }

        it "should return an Array of the element" do
          expect(subject.apply({list: element})).to be == [element]
        end
      end

      context "when given multiple elements" do
        let(:elements) { %w[foo bar baz] }

        it "should return the elements" do
          expect(subject.apply({list: elements})).to be == elements
        end
      end
    end

    describe "name" do
      let(:string) { 'foo' }
      let(:name)   { :foo }

      it "should return a Hash with the name and true" do
        expect(subject.apply({name: string})).to be == {name => true}
      end

      context "when given mixed-case String" do
        let(:string) { 'fooBar' }
        let(:name)   { :foobar  }

        it "should downcase the String" do
          expect(subject.apply({name: string})).to be == {name => true}
        end
      end

      context "when given a hyphenated String" do
        let(:string) { 'foo-bar' }
        let(:name)   { :foo_bar  }

        it "should replace the hyphens with underscores" do
          expect(subject.apply({name: string})).to be == {name => true}
        end
      end
    end

    describe "name with simple value" do
      let(:string) { 'foo' }
      let(:name)   { :foo  }
      let(:value)  { 'bar' }

      it "should return a Hash of the name and value" do
        expect(subject.apply({name: string, value: value})).to be == {
          name => value
        }
      end
    end

    describe "name with values" do
      let(:string) { 'foo' }
      let(:name)   { :foo  }
      let(:value)  { {'x' => 1} }

      it "should return a Hash of the name and value" do
        expect(subject.apply({name: string, values: value})).to be == {
          name => value
        }
      end
    end

    describe "directives" do
      context "when given a single Hash" do
        let(:hash) { {foo: 'bar'} }

        it "should return the Hash" do
          expect(subject.apply({directives: hash})).to be == hash
        end
      end

      context "when given multiple Hashes" do
        let(:hash1)  { {foo: 'bar'} }
        let(:hash2)  { {baz: 'quix'} }
        let(:hashes) { [hash1, hash2] }
        let(:hash)   { hash1.merge(hash2) }

        it "should return a merged Hash" do
          expect(subject.apply({directives: hashes})).to be == hash
        end

        context "when the Hashes share key names" do
          let(:hash1)  { {foo: '1', bar: '2'} }
          let(:hash2)  { {bar: '3', baz: '4'} }
          let(:hashes) { [hash1, hash2]      }
          let(:hash)   { {foo: '1', bar: ['2', '3'], baz: '4'} }

          it "should combine the values into an Array" do
            expect(subject.apply({directives: hashes})).to be == hash
          end
        end
      end
    end
  end
end
