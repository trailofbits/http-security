# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'http/security/version'

Gem::Specification.new do |gem|
  gem.name          = "http-security"
  gem.version       = HTTP::Security::VERSION
  gem.authors       = ["Dominic Owen", "Hal Brodigan"]
  gem.email         = ["dwowen20@gmail.com", "hal@trailofbits.com"]
  gem.summary       = %q{HTTP Security Header Parser}
  gem.description   = %q{HTTP Security Header Parser}
  gem.homepage      = "https://github.com/trailofbits/http-security#readme"
  gem.license       = "MIT"

  gem.files         = `git ls-files`.split($/)
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
  gem.required_ruby_version = '>= 3.1.0'

  gem.add_dependency 'parslet', '~> 2.0'
  gem.add_development_dependency "bundler", "~> 2.0"
end
