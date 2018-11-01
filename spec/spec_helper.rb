require 'simplecov'
SimpleCov.start

require 'rspec'
require 'http/security/version'

include HTTP::Security

RSpec.configure do |specs|
  specs.filter_run_excluding :gauntlet
end
