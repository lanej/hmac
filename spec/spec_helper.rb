require File.expand_path("../../lib/ey-hmac", __FILE__)

Bundler.require(:test)

Dir[File.expand_path("../{support,shared}/*.rb", __FILE__)].each{|f| require(f)}

RSpec.configure do |config|
  config.order = "random"
end
