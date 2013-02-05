require "ey-hmac/version"

require 'base64'
require 'digest/md5'
require 'openssl'

module Ey
  module Hmac
    Error = Class.new(StandardError)

    MissingSecret        = Class.new(Error)
    MissingAuthorization = Class.new(Error)
    SignatureMismatch    = Class.new(Error)

    autoload :Adapter, "ey-hmac/adapter"
    autoload :Faraday, "ey-hmac/faraday"
    autoload :Rack, "ey-hmac/rack"

    def self.default_adapter=(default_adapter)
      @default_adapter = default_adapter
    end

    def self.default_adapter
      @default_adapter ||= begin
                             if defined?(Rack) || defined?(Rails)
                               Ey::Hmac::Adapter::Rack
                             elsif defined?(Faraday)
                               Ey::Hmac::Adapter::Rails
                             end
                           end
    end

    # @example
    #   Ey::Hmac.sign!(env, @key_id, @key_secret)
    #
    # @param request [Hash] request environment
    # @option options [Ey::Hmac::Adapter] :adapter (#{default_adapter}) adapter to sign request with
    # @option options [Integer] :version (nil) signature version
    # @option options [String] :authorization_header ('Authorization') Authorization header key.
    # @option options [String] :server ('EyHmac') service name prefixed to {#authorization}
    # @see {Ey::Hmac::Adapter#sign!}
    def self.sign!(request, key_id, key_secret, options={})
      adapter = options[:adapter] || Ey::Hmac.default_adapter

      raise ArgumentError, "Missing adapter and Ey::Hmac.default_adapter" unless adapter

      adapter.new(request, options).sign!(key_id, key_secret)
    end

    # @example
    #   Ey::Hmac.authenticated? do |key_id|
    #     @consumer = Consumer.where(auth_id: key_id).first
    #     @consumer && @consumer.auth_key
    #   end
    # @param request [Hash] request environment
    # @option options [Ey::Hmac::Adapter] :adapter ({#default_adapter}) adapter to verify request with
    # @see {Ey::Hmac::Adapter#authenticated?}
    def self.authenticated?(request, options={}, &block)
      adapter = options[:adapter] || Ey::Hmac.default_adapter

      raise ArgumentError, "Missing adapter and Ey::Hmac.default_adapter" unless adapter

      adapter.new(request, options).authenticated?(&block)
    end

    # @example
    #   Ey::Hmac.authenticate! do |key_id|
    #     @consumer = Consumer.where(auth_id: key_id).first
    #     @consumer && @consumer.auth_key
    #   end
    # @param request [Hash] request environment
    # @option options [Ey::Hmac::Adapter] :adapter ({#default_adapter}) adapter to verify request with
    # @see {Ey::Hmac::Adapter#authenticate!}
    def self.authenticate!(request, options={}, &block)
      adapter = options[:adapter] || Ey::Hmac.default_adapter

      raise ArgumentError, "Missing adapter and Ey::Hmac.default_adapter" unless adapter

      adapter.new(request, options).authenticate!(&block)
    end
  end
end
