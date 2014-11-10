require "codeclimate-test-reporter"
CodeClimate::TestReporter.start

require 'rspec'
require 'security_headers/version'

include SecurityHeaders

RSpec.configure do |specs|
  specs.filter_run_excluding :gauntlet
end