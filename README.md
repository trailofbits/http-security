Security Headers
=====

[![Code Climate](https://codeclimate.com/github/trailofbits/securityheaders.png)](https://codeclimate.com/github/trailofbits/securityheaders) [![Build Status](https://travis-ci.org/trailofbits/securityheaders.svg)](https://travis-ci.org/trailofbits/securityheaders)

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
