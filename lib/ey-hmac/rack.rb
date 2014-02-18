# Request middleware that performs HMAC request signing
class Ey::Hmac::Rack
  attr_reader :key_id, :key_secret, :options

  def initialize(app, key_id, key_secret, options = {})
    @app = app
    @key_id, @key_secret = key_id, key_secret
    @options = options
  end

  def call(env)
    Ey::Hmac.sign!(env, key_id, key_secret, { adapter: Ey::Hmac::Adapter::Rack }.merge(options))

    @app.call(env)
  end
end
