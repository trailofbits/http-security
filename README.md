# HTTP Security

* [Source](https://github.com/trailofbits/http-security)
* [Issues](https://github.com/trailofbits/http-security/issues)
* [Documentation](https://rubydoc.info/gems/http-security/frames)

[![Code Climate](https://codeclimate.com/github/trailofbits/http-security.png)](https://codeclimate.com/github/trailofbits/http-security) [![Build Status](https://travis-ci.org/trailofbits/http-security.svg)](https://travis-ci.org/trailofbits/http-security) [![Test Coverage](https://codeclimate.com/github/trailofbits/http-security/badges/coverage.svg)](https://codeclimate.com/github/trailofbits/http-security)

Security Headers is a parser for security-relevant HTTP headers. Each header
value is parsed and validated according to the syntax specified in its relevant 
RFC.

Security Headers relies on [parslet] for constructing its parsing grammar.

Currently parsed security headers are:

* `Cache-Control`
* `Content-Security-Policy`
* `Content-Security-Policy-Report-Only`
* `Expires`
* `Pragma`
* `Public-Key-Pins`
* `Public-Key-Pins-Report-Only`
* `Set-Cookie`
* `Strict-Transport-Security`
* `X-Content-Type-Options`
* `X-Frame-Options`
* `X-Permitted-Cross-Domain-Policies`
* `X-XSS-Protection

## Example

    require 'net/https'
    response = Net::HTTP.get_response(URI('https://twitter.com/'))

    require 'http/security'
    headers = HTTP::Security::Response.parse(response)

    headers.cache_control
    # => #<HTTP::Security::Headers::CacheControl:0x00000002f65778 @private=nil, @max_age=nil, @no_cache=true>

    headers.content_security_policy
    # => #<HTTP::Security::Headers::ContentSecurityPolicy:0x00000002d8e238 @default_src="https:"@12, @script_src="'unsafe-inline' 'unsafe-eval' https:"@172, @object_src="https:"@153, @style_src="'unsafe-inline' https:"@220, @img_src="https: blob: data:"@98, @media_src="https: blob:"@128, @frame_src="https: twitter:"@73, @font_src="https: data:"@49, @connect_src="https:"@32, @report_uri=[#<URI::HTTPS:0x00000002d94250 URL:https://twitter.com/i/csp_report?a=NVQWGYLXFVZXO2LGOQ%3D%3D%3D%3D%3D%3D&ro=false;>], @sandbox=nil>

    headers.expires
    # => #<HTTP::Security::HTTPDate: Tue, 31 Mar 1981 00:00:00 GMT ((2444695j,0s,0n),+0s,2299161j)>

    headers.pragma
    # => #<HTTP::Security::Headers::Pragma:0x00000002ccc5e8 @no_cache=true>

    headers.strict_transport_security
    # => #<HTTP::Security::Headers::StrictTransportSecurity:0x00000002c928c0 @max_age=631138519, @include_sub_domains=nil>

    headers.x_content_type_options
    # => #<HTTP::Security::Headers::XContentTypeOptions:0x00000002a46e40 @no_sniff=true>

    headers.x_frame_options
    # => #<HTTP::Security::Headers::XFrameOptions:0x000000028163c8 @deny=nil, @same_origin=true, @allow_from=nil, @allow_all=nil>

    headers.x_permitted_cross_domain_policies
    # => nil

    headers.x_xss_protection
    # => #<HTTP::Security::Headers::XXSSProtection:0x0000000297a408 @enabled=true, @mode="block"@8, @report=nil>

## Requirements

* [ruby] >= 1.9.1
* [parslet] ~> 1.5

## Install

    $ gem install http-security

## Testing

To run the RSpec tests:

    $ rake spec

To test the parser against the Alexa Top 100:

    $ rake spec:gauntlet

## License

See the {file:LICENSE.txt} file.

[ruby]: https://www.ruby-lang.org/
[parslet]: http://kschiess.github.io/parslet/
