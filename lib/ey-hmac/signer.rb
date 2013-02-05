# This class is responsible for forming the canonical string to used to sign requests
# @abstract override methods {#request_method}, {#path}, {#body}, {#headers} to fulfill contract
class Ey::Hmac::Signer
  AUTHORIZATION_REGEXP = /\w+ ([^:]+):(.+)$/

  autoload :Rack, "ey-hmac/signer/rack"
  autoload :Faraday, "ey-hmac/signer/faraday"

  attr_reader :request, :options, :authorization_header, :service

  # @param [Object] request signer-specific request implementation
  # @option options [Integer] :version signature version
  # @option options [String] :authorization_header ('Authorization') Authorization header key.
  # @option options [String] :server ('EyHmac') service name prefixed to {#authorization}
  def initialize(request, options={})
    @request, @options = request, options

    @authorization_header = options[:authorization_header] || 'Authorization'
    @service = options[:service] || 'EyHmac'
  end

  # In order for the server to correctly authorize the request, the client and server MUST AGREE on the method used to form {#String}
  # @return [String] canonical string used to form the {#signature}
  # default canonical string formation is
  # {#request_method} + "\n" +
  # {#content_type}   + "\n" +
  # {#content_md5}    + "\n" +
  # {#date}           + "\n" +
  # {#path}
  def canonicalize
    [request_method, content_type, content_md5, date, path].join("/n")
  end

  # @param [String] key_secret private HMAC key
  # @return [String] HMAC signature of {#request}
  def signature(key_secret)
    Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('sha1'), key_secret, canonicalize)).strip
  end

  # @param [String] key_id public HMAC key
  # @param [String] key_secret private HMAC key
  # @return [String] HMAC header value of {#request}
  def authorization(key_id, key_secret)
    "#{service} #{key_id}:#{signature(key_secret)}"
  end

  # @abstract
  # @return [String] upcased verb. i.e. 'GET'
  def request_method
    raise NotImplementedError
  end

  # @abstract
  # @return [String] request path. i.e. '/blogs/1'
  def path
    raise NotImplementedError
  end

  # @abstract
  # @return [String] request body.
  def body
    raise NotImplementedError
  end

  # @abstract
  # @return [String] value of the Content-Type header in {#request}
  def content_type
    raise NotImplementedError
  end

  # @abstract
  # @return [String] value of the Date header in {#request}.
  # @see {Time#http_date}
  def date
    raise NotImplementedError
  end

  # @abstract
  # Add {#signature} header to request. Typically this is 'Authorization' or 'WWW-Authorization'
  def sign!(key_id, key_secret)
    raise NotImplementedError
  end

  # @abstract
  # @return [String] value of the {#authorization_header}
  def authorization_signature
    raise NotImplementedError
  end

  # Check {#authorization_signature} against calculated {#signature}
  # @example
  #   Ey::Hmac.authenticated? do |key_id|
  #     @consumer = Consumer.where(auth_id: key_id).first
  #     @consumer && @consumer.auth_key
  #   end
  # @yieldparams key_id [String] public HMAC key
  # @return [Boolean] true if block yields matching private key and signature matches, else false
  def authenticated?(&block)
    if authorization_match = AUTHORIZATION_REGEXP.match(authorization_signature)
      key_id          = authorization_match[1]
      signature_value = authorization_match[2]

      key_secret = block.call(key_id)
      key_secret && (signature_value == signature(key_secret))
    else
      false
    end
  end
end
