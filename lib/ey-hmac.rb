require "ey-hmac/version"

require 'base64'
require 'digest/md5'
require 'openssl'

module Ey
  module Hmac
    autoload :Adapter, "ey-hmac/adapter"
    autoload :Faraday, "ey-hmac/faraday"

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

    def self.sign!(request, key_id, key_secret, options={})
      adapter = options[:adapter] || Ey::Hmac.default_adapter

      raise ArgumentError, "Missing adapter and Ey::Hmac.default_adapter" unless adapter

      adapter.new(request, options).sign!(key_id, key_secret)
    end

    def self.authenticated?(request, options={}, &block)
      adapter = options[:adapter] || Ey::Hmac.default_adapter

      raise ArgumentError, "Missing adapter and Ey::Hmac.default_adapter" unless adapter

      adapter.new(request, options).authenticated?(&block)
    end
  end
end
