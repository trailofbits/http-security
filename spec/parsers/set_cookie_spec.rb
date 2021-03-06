require "spec_helper"
require "http/security/parsers/set_cookie"

describe Parsers::SetCookie do
  it "accepts 'name=value'" do
    expect(subject.parse('foo=bar')).to be == [{cookie: {foo: 'bar'}}]
  end

  it "accepts 'name=value; Expires=...'" do
    expires = "Wed, 09 Jun 2021 10:18:14 GMT"

    expect(subject.parse("foo=bar; Expires=#{expires}")).to be == [{
      cookie:  {foo: 'bar'},
      expires: Date.parse(expires)
    }]
  end

  it "accepts 'name=value; Path=...; Expires=...; Secure; Domain=...; HttpOnly'" do
    path    = '/accounts'
    expires = "Wed, 09 Jun 2021 10:18:14 GMT"
    domain  = '.example.com'

    expect(subject.parse("foo=bar; Path=#{path}; Expires=#{expires}; Secure; Domain=#{domain}; HttpOnly")).to be == [{
      cookie:    {foo: 'bar'},
      path:      path,
      expires:   Date.parse(expires),
      secure:    'Secure',
      domain:    domain,
      http_only: 'HttpOnly'
    }]
  end

  it "accepts multiple cookie values" do
    path = '/'
    domain = '.twitter.com'
    expires = 'Sat, 19 Nov 2016 00:27:36 GMT'

    expect(subject.parse("foo=bar; Path=#{path}; Domain=#{domain}; Secure; HTTPOnly, bar=baz; Domain=#{domain}; Path=#{path}; Expires=#{expires}")).to be == [
      {
        cookie:    {foo: 'bar'},
        path:      path,
        domain:    domain,
        secure:    'Secure',
        http_only: 'HTTPOnly'
      },

      {
        cookie:  {bar: 'baz'},
        domain:  domain,
        path:    path,
        expires: Date.parse(expires)
      }
    ]
  end
end
