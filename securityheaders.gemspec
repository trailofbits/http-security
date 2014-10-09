# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'security_headers/version'

Gem::Specification.new do |gem|
  gem.name          = "securityheaders"
  gem.version       = SecurityHeaders::VERSION
  gem.authors       = ["Dominic Owen"]
  gem.email         = ["dwowen20@gmail.com"]
  gem.summary       = %q{Security Header Parser}
  gem.description   = %q{Security Header Parser}
  gem.homepage      = "https://github.com/trailofbits/securityheaders#readme"
  gem.license       = "MIT"

  #gem.files         = `git ls-files -z`.split("\x0")
  gem.files         = `git ls-files`.split($/)
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.add_dependency 'parslet', '~> 1.5'
  gem.add_development_dependency "bundler", "~> 1.7"
end
