require 'rspec'
require 'security_headers/version'

include SecurityHeaders

RSpec.configure do |specs|
  specs.filter_run_excluding :gauntlet
end