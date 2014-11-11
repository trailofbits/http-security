Security Headers
=====

[![Code Climate](https://codeclimate.com/github/trailofbits/securityheaders.png)](https://codeclimate.com/github/trailofbits/securityheaders) [![Build Status](https://travis-ci.org/trailofbits/securityheaders.svg)](https://travis-ci.org/trailofbits/securityheaders) [![Test Coverage](https://codeclimate.com/github/trailofbits/securityheaders/badges/coverage.svg)](https://codeclimate.com/github/trailofbits/securityheaders)

Security Headers is a parser for security-relevant HTTP headers. Each header value is parsed and validated according to the syntax specified in its relevant RFC.

Security Headers relies on [parslet] for constructing its parsing grammer, and [curb] for retrieving raw HTTP headers.

Currently parsed security headers are:

* X-Frame-Options
* Strict-Transport-Security
* X-Content-Type-Options
* X-XSS-Protection
* Cache-Control
* Pragma
* Expires
* X-Permitted-Cross-Domain-Policies
* Content-Security-Policy
* Content-Security-Policy-Report-Only

Example
-------

    require 'security_headers'
    headers = SecurityHeaders::Request.parse_headers("http://www.google.com")

parse_headers returns an array of hashes, with non security headers given a key of 'excluded'. Pretty printing the result from above returns:

    [{:excluded=>"HTTP/1.1 200 OK"@0},
     {:excluded=>"Date: Tue, 11 Nov 2014 02:57:15 GMT"@17},
     {:expires=>"-1"@63},
     {:cache_control=>"private, max-age=0"@82},
     {:excluded=>"Content-Type: text/html; charset=ISO-8859-1"@102},
     {:excluded=>
       "Set-Cookie: ..."@147},
     {:excluded=>
       "Set-Cookie: ..."@304},
     {:excluded=>
       "P3P: CP=\"This is not a P3P policy! See http://www.google.com/support/accounts/bin/answer.py?hl=en&answer=151657 for more info.\""@530},
     {:excluded=>"Server: gws"@659},
     {:x_xss_protection=>"1; mode=block"@690},
     {:x_frame_options=>"SAMEORIGIN"@722},
     {:excluded=>"Alternate-Protocol: 80:quic,p=0.01"@734},
     {:excluded=>"Transfer-Encoding: chunked"@770}]

Requirements
------------

* [parslet] ~> 1.5
* [curb] ~> 0.7.16

Install
-------

    $ gem install securityheaders

Testing
-------

To run the RSpec tests:

    $ rake spec

To test the parser against the Alexa Top 100:

    $ rake spec:gauntlet

License
-------

See the {file:LICENSE.txt} file.

[parslet]: http://kschiess.github.io/parslet/
[curb]: https://github.com/taf2/curb/