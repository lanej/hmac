# frozen_string_literal: true

require File.expand_path('../lib/ey-hmac', __dir__)

Bundler.require(:test)
require 'securerandom'

Dir[File.expand_path('{support,shared}/*.rb', __dir__)].sort.each { |f| require(f) }

RSpec.configure do |config|
  config.order = 'random'
end
