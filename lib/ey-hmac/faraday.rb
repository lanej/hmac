require 'faraday'

if Faraday.respond_to? :register_middleware
  Faraday.register_middleware(:request, {:ey_hmac => lambda { Ey::Hmac::Faraday }})
end

# Request middleware that performs HMAC request signing
class Ey::Hmac::Faraday < Faraday::Middleware
  dependency do
    require 'ey-hmac' unless defined?(Ey::Hmac)
  end

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
