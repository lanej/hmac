# This class is responsible for forming the canonical string to used to sign requests
# @abstract override methods {#method}, {#path}, {#body}, {#content_type} and {#content_digest}
class Ey::Hmac::Adapter
  AUTHORIZATION_REGEXP = /\w+ ([^:]+):(.+)$/

  autoload :Rack, "ey-hmac/adapter/rack"
  autoload :Faraday, "ey-hmac/adapter/faraday"

  attr_reader :request, :options, :authorization_header, :service, :sign_with, :accept_digests

  # @param [Object] request signer-specific request implementation
  # @option options [Integer] :version signature version
  # @option options [String] :authorization_header ('Authorization') Authorization header key.
  # @option options [String] :server ('EyHmac') service name prefixed to {#authorization}. set to {#service}
  # @option options [Symbol] :sign_with (:sha_256) outgoing signature digest algorithm. See {OpenSSL::Digest#new}
  # @option options [Array] :accepted_digests ([:sha_256]) accepted incoming signature digest algorithm. See {OpenSSL::Digest#new}
  def initialize(request, options={})
    @request, @options = request, options

    @authorization_header = options[:authorization_header] || 'Authorization'
    @service              = options[:service] || 'EyHmac'
    @sign_with            = options[:sign_with] || :sha256
    @accept_digests       = Array(options[:accept_digests] || :sha256)
  end

  # In order for the server to correctly authorize the request, the client and server MUST AGREE on this format
  #
  # default canonical string formation is '{#method}\\n{#content_type}\\n{#content_digest}\\n{#date}\\n{#path}'
  # @return [String] canonical string used to form the {#signature}
  def canonicalize
    [method, content_type, content_digest, date, path].join("\n")
  end

  # @param [String] key_secret private HMAC key
  # @param [String] signature digest hash function. Defaults to #sign_with
  # @return [String] HMAC signature of {#request}
  def signature(key_secret, digest = self.sign_with)
    Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new(digest.to_s), key_secret, canonicalize)).strip
  end

  # @param [String] key_id public HMAC key
  # @param [String] key_secret private HMAC key
  # @return [String] HMAC header value of {#request}
  def authorization(key_id, key_secret)
    "#{service} #{key_id}:#{signature(key_secret, sign_with)}"
  end

  # @abstract
  # @return [String] upcased request verb. i.e. 'GET'
  def method
    raise NotImplementedError
  end

  # @abstract
  # @return [String] request path. i.e. '/blogs/1'
  def path
    raise NotImplementedError
  end

  # @abstract
  # Digest of body. Default is MD5.
  # @return [String] digest of body
  def content_digest
    raise NotImplementedError
  end

  # @abstract
  # @return [String] request body.
  # @return [NilClass] if there is no body or the body is empty
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
  # @see Time#http_date
  def date
    raise NotImplementedError
  end

  # @abstract used when verifying a signed request
  # @return [String] value of the {#authorization_header}
  def authorization_signature
    raise NotImplementedError
  end

  # @abstract
  # Add {#signature} header to request. Typically this is 'Authorization' or 'WWW-Authorization'
  # @return [String] calculated {#authorization}
  # @see Ey::Hmac#sign!
  def sign!(key_id, key_secret)
    raise NotImplementedError
  end

  # Check {#authorization_signature} against calculated {#signature}
  # @yieldparam key_id [String] public HMAC key
  # @return [Boolean] true if block yields matching private key and signature matches, else false
  # @see #authenticated!
  def authenticated?(options={}, &block)
    authenticated!(&block)
  rescue Ey::Hmac::Error
    false
  end

  # @see Ey::Hmac#authenticate!
  def authenticated!(&block)
    unless authorization_match = AUTHORIZATION_REGEXP.match(authorization_signature)
      raise(Ey::Hmac::MissingAuthorization, "Failed to parse authorization_signature #{authorization_signature}")
    end

    key_id          = authorization_match[1]
    signature_value = authorization_match[2]

    unless key_secret = block.call(key_id)
      raise(Ey::Hmac::MissingSecret, "Failed to find secret matching #{key_id.inspect}")
    end

    calculated_signatures = self.accept_digests.map { |ad| signature(key_secret, ad) }

    unless calculated_signatures.any? { |cs| secure_compare(signature_value, cs) }
      raise(Ey::Hmac::SignatureMismatch, "Calculated signature #{signature_value} does not match #{calculated_signatures.inspect} using #{canonicalize.inspect}")
    end
    true
  end
  alias authenticate! authenticated!

  # Constant time string comparison.
  # pulled from https://github.com/rack/rack/blob/master/lib/rack/utils.rb#L399
  def secure_compare(a, b)
    return false unless a.bytesize == b.bytesize

    l = a.unpack("C*")

    r, i = 0, -1
    b.each_byte { |v| r |= v ^ l[i+=1] }
    r == 0
  end
end
