require 'rack'

class Ey::Hmac::Adapter::Rack < Ey::Hmac::Adapter
  def initialize(request, options)
    super
    @request = ::Rack::Request.new(request) if request.is_a?(Hash)
  end

  def method
    request.request_method.to_s.upcase
  end

  def content_type
    request.content_type
  end

  def content_digest
    request.env['HTTP_CONTENT_DIGEST'] ||= body && Digest::MD5.hexdigest(body)
  end
  
  def body
    if request.env["rack.input"]
      request.env["rack.input"].rewind
      body = request.env["rack.input"].read
      request.env["rack.input"].rewind
      body == "" ? nil : body
    else nil
    end
  end

  def date
    request.env['HTTP_DATE'] ||= Time.now.httpdate
  end

  def path
    request.path
  end

  def sign!(key_id, key_secret)
    if options[:version]
      request.env['HTTP_X_SIGNATURE_VERSION'] = options[:version]
    end

    request.env["HTTP_#{authorization_header.to_s.upcase}"] = authorization(key_id, key_secret)
  end

  def authorization_signature
    request.env["HTTP_#{authorization_header.to_s.upcase}"]
  end
end
