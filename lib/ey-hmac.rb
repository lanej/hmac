require "ey-hmac/version"

require 'base64'
require 'digest/md5'
require 'openssl'

module Ey
  module Hmac
    autoload :Signer, "ey-hmac/signer"
    autoload :Reader, "ey-hmac/reader"

    def self.default_reader=(default_reader)
      @default_reader = default_reader
    end

    def self.default_reader
      @@default_reader
    end

    def self.default_signer=(default_signer)
      @default_signer = default_signer
    end

    def self.default_signer
      @@default_signer
    end

    def self.sign!(request, key_id, key_secret, options={})
      signer = options[:signer] || Ey::Hmac.default_signer

      raise ArgumentError, "Missing signer and Ey::Hmac.default_signer" unless signer

      signer.new(request, options).sign!(key_id, key_secret)
    end

    def self.authenticated?(request, options={}, &block)
      reader = options[:reader] || Ey::Hmac.default_reader

      raise ArgumentError, "Missing reader and Ey::Hmac.default_reader" unless reader

      reader.new(request, options).authenticated?(&block)
    end
  end
end
