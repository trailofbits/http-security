require "spec_helper"
require "http/security/parsers/set_cookie"

describe Parsers::SetCookie do
  it "accepts 'name=value'" do
    expect(subject.parse('foo=bar')).to be == [{cookie: {foo: 'bar'}}]
  end

  it "accepts 'name=value; Expires=...'" do
    expires = "Wed, 09 Jun 2021 10:18:14 GMT"

    expect(subject.parse("foo=bar; Expires=#{expires}")).to be == [{
      cookie: {foo: 'bar'},
      expires: expires
    }]
  end

  it "accepts 'name=value; Path=...; Expires=...; Secure; Domain=...; HttpOnly'" do
    path    = '/accounts'
    expires = "Wed, 09 Jun 2021 10:18:14 GMT"
    domain  = '.example.com'

    expect(subject.parse("foo=bar; Path=#{path}; Expires=#{expires}; Secure; Domain=#{domain}; HttpOnly")).to be == [{
      cookie: {foo: 'bar'},
      path: path,
      expires: expires,
      secure: 'Secure',
      domain: domain,
      http_only: 'HttpOnly'
    }]
  end
end
