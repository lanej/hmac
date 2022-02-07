# frozen_string_literal: true

require 'spec_helper'
require 'securerandom'

describe 'rack' do
  before(:all) { Bundler.require(:rack) }

  let!(:key_id)     { SecureRandom.hex(8) }
  let!(:key_secret) { SecureRandom.hex(16) }

  describe 'adapter' do
    let(:adapter) { Ey::Hmac::Adapter::Rack }

    it 'signs and read request' do
      request = Rack::Request.new(
        'rack.input' => StringIO.new('{1: 2}'),
        'HTTP_CONTENT_TYPE' => 'application/json'
      )
      Ey::Hmac.sign!(request, key_id, key_secret, adapter: adapter)

      expect(request.env['HTTP_AUTHORIZATION']).to start_with('EyHmac')
      expect(request.env['HTTP_CONTENT_DIGEST']).to eq(Digest::MD5.hexdigest(request.body.tap(&:rewind).read))
      expect(Time.parse(request.env['HTTP_DATE'])).not_to be_nil

      yielded = false

      expect(Ey::Hmac).to be_authenticated(request, adapter: adapter) do |key_id|
        expect(key_id).to eq(key_id)
        yielded = true
        key_secret
      end

      expect(yielded).to be_truthy
    end

    it 'does not set Content-Digest if body is nil' do
      request = Rack::Request.new(
        'HTTP_CONTENT_TYPE' => 'application/json'
      )

      Ey::Hmac.sign!(request, key_id, key_secret, adapter: adapter)

      expect(request.env['HTTP_AUTHORIZATION']).to start_with('EyHmac')
      expect(request.env).not_to have_key('HTTP_CONTENT_DIGEST')
      expect(Time.parse(request.env['HTTP_DATE'])).not_to be_nil

      yielded = false

      expect(Ey::Hmac).to be_authenticated(request, adapter: adapter) do |key_id|
        expect(key_id).to eq(key_id)
        yielded = true
        key_secret
      end

      expect(yielded).to be_truthy
    end

    it 'does not set Content-Digest if body is empty' do
      request = Rack::Request.new(
        'rack.input' => StringIO.new(''),
        'HTTP_CONTENT_TYPE' => 'application/json'
      )

      Ey::Hmac.sign!(request, key_id, key_secret, adapter: adapter)

      expect(request.env['HTTP_AUTHORIZATION']).to start_with('EyHmac')
      expect(request.env).not_to have_key('HTTP_CONTENT_DIGEST')
      expect(Time.parse(request.env['HTTP_DATE'])).not_to be_nil

      yielded = false

      expect(Ey::Hmac).to be_authenticated(request, adapter: adapter) do |key_id|
        expect(key_id).to eq(key_id)
        yielded = true
        key_secret
      end

      expect(yielded).to be_truthy
    end

    context 'with a request' do
      let(:request) do
        Rack::Request.new(
          'rack.input' => StringIO.new('{1: 2}'),
          'HTTP_CONTENT_TYPE' => 'application/json'
        )
      end

      include_examples 'authentication'
    end
  end

  describe 'middleware' do
    it 'accepts a SHA1 signature' do
      app = lambda do |env|
        authenticated = Ey::Hmac.authenticated?(env, accept_digests: %i[sha1 sha256],
                                                     adapter: Ey::Hmac::Adapter::Rack) do |auth_id|
          (auth_id == key_id) && key_secret
        end
        [(authenticated ? 200 : 401), { 'Content-Type' => 'text/plain' }, []]
      end

      outer_key_id = key_id
      outer_key_secret = key_secret
      client = Rack::Client.new do
        use Ey::Hmac::Rack, outer_key_id, outer_key_secret, sign_with: :sha1
        run app
      end

      expect(client.get('/resource').status).to eq(200)
    end

    it 'accepts a SHA256 signature' do # default
      app = lambda do |env|
        authenticated = Ey::Hmac.authenticated?(env, adapter: Ey::Hmac::Adapter::Rack) do |auth_id|
          (auth_id == key_id) && key_secret
        end
        [(authenticated ? 200 : 401), { 'Content-Type' => 'text/plain' }, []]
      end

      outer_key_id = key_id
      outer_key_secret = key_secret
      client = Rack::Client.new do
        use Ey::Hmac::Rack, outer_key_id, outer_key_secret
        run app
      end

      expect(client.get('/resource').status).to eq(200)
    end

    it 'accepts multiple digest signatures' do # default
      require 'ey-hmac/faraday'
      Bundler.require(:rack)

      app = lambda do |env|
        authenticated = Ey::Hmac.authenticated?(env, adapter: Ey::Hmac::Adapter::Rack) do |auth_id|
          (auth_id == key_id) && key_secret
        end
        [(authenticated ? 200 : 401), { 'Content-Type' => 'text/plain' }, []]
      end

      connection = Faraday.new do |c|
        c.use :hmac, key_id, key_secret, digest: %i[sha1 sha256]
        c.adapter(:rack, app)
      end

      expect(connection.get('/resources').status).to eq(200)
    end
  end
end
