require 'ey-hmac'
require 'faraday'

class Ey::Hmac::Faraday < Faraday::Response::Middleware
  dependency("ey-hmac")

  attr_reader :key_id, :key_secret, :options

  def initialize(app, key_id, key_secret, options = {})
    super(app)
    @key_id, @key_secret = key_id, key_secret
    @options = options
  end

  def call(env)
    Ey::Hmac.sign!(env, key_id, key_secret, {adapter: Ey::Hmac::Adapter::Faraday}.merge(options))
    @app.call(env)
  end
end

Faraday::Middleware.register_middleware :hmac => Ey::Hmac::Faraday
