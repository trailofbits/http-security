if ENV['CODECLIMATE_REPO_TOKEN']
  require "codeclimate-test-reporter"
  CodeClimate::TestReporter.start
end

require 'rspec'
require 'http/security/version'

include HTTP::Security

RSpec.configure do |specs|
  specs.filter_run_excluding :gauntlet
end
