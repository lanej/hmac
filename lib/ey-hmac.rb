# frozen_string_literal: true

require 'ey-hmac/version'

require 'base64'
require 'digest/md5'
require 'openssl'
require 'time'

module Ey::Hmac
  Error = Class.new(StandardError)

  MissingSecret        = Class.new(Error)
  MissingAuthorization = Class.new(Error)
  SignatureMismatch    = Class.new(Error)
  ExpiredHmac          = Class.new(Error)

  autoload :Adapter, 'ey-hmac/adapter'
  autoload :Faraday, 'ey-hmac/faraday'
  autoload :Rack, 'ey-hmac/rack'

  def self.default_adapter=(default_adapter)
    @default_adapter = default_adapter
  end

  def self.default_adapter
    @default_adapter ||= if defined?(::Rack) || defined?(::Rails)
                           Ey::Hmac::Adapter::Rack
                         elsif defined?(::Faraday)
                           Ey::Hmac::Adapter::Faraday
                         end
  end

  # Signs request by calculating signature and adding it to the specified header
  # @example
  #   Ey::Hmac.sign!(env, @key_id, @key_secret)
  #
  # @see Ey::Hmac::Adapter#sign!
  #
  # @param request [Hash] request environment
  # @option options [Ey::Hmac::Adapter] :adapter (#{default_adapter}) adapter to sign request with
  # @option options [Integer] :version (nil) signature version
  # @option options [String] :authorization_header ('Authorization') Authorization header key.
  # @option options [String] :service ('EyHmac') service name prefixed to {Ey::Hmac::Adapter#authorization}
  #
  # @return [String] authorization signature
  def self.sign!(request, key_id, key_secret, options = {})
    adapter = options[:adapter] || Ey::Hmac.default_adapter

    raise ArgumentError, 'Missing adapter and Ey::Hmac.default_adapter' unless adapter

    adapter.new(request, options).sign!(key_id, key_secret)
  end

  # @example
  #   Ey::Hmac.authenticated? do |key_id|
  #     @consumer = Consumer.where(auth_id: key_id).first
  #     @consumer && @consumer.auth_key
  #   end
  #
  # @see Ey::Hmac::Adapter#authenticated?
  # @see Ey::Hmac#authenticate!
  #
  # @param request [Hash] request environment
  # @option options [Ey::Hmac::Adapter] :adapter ({#default_adapter}) adapter to verify request with
  # @yieldparam key_id [String] public HMAC key
  #
  # @return [Boolean] success of authentication
  def self.authenticated?(request, options = {}, &block)
    adapter = options[:adapter] || Ey::Hmac.default_adapter

    raise ArgumentError, 'Missing adapter and Ey::Hmac.default_adapter' unless adapter

    adapter.new(request, options).authenticated?(&block)
  end

  # Check {Ey::Hmac::Adapter#authorization_signature} against calculated {Ey::Hmac::Adapter#signature}
  # @example
  #   Ey::Hmac.authenticate! do |key_id|
  #     @consumer = Consumer.where(auth_id: key_id).first
  #     @consumer && @consumer.auth_key
  #   end
  #
  # @see Ey::Hmac::Adapter#authenticate!
  #
  # @param request [Hash] request environment
  # @yieldparam key_id [String] public HMAC key
  # @option options [Ey::Hmac::Adapter] :adapter ({#default_adapter}) adapter to verify request with
  #
  # @raise [SignatureMismatch] if the value of {Ey::Hmac::Adapter#authorization_signature} does not
  #   match {Ey::Hmac::Adapter#signature}
  # @raise [MissingSecret] if the block does not return a private key matching +key_id+
  # @raise [MissingAuthorization] if the value of {Ey::Hmac::Adapter#authorization_signature} is nil
  # @return [TrueClass] if authentication was successful
  def self.authenticate!(request, options = {}, &block)
    adapter = options[:adapter] || Ey::Hmac.default_adapter

    raise ArgumentError, 'Missing adapter and Ey::Hmac.default_adapter' unless adapter

    adapter.new(request, options).authenticate!(&block)
  end
end
