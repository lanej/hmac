# frozen_string_literal: true

require 'rack'

class Ey::Hmac::Adapter::Rack < Ey::Hmac::Adapter
  def initialize(request, options)
    super
    @request = request.is_a?(Hash) ? ::Rack::Request.new(request) : request
  end

  def method
    request.request_method.to_s.upcase
  end

  def content_type
    request.content_type
  end

  def content_digest
    request.env['HTTP_CONTENT_DIGEST']
  end

  def set_content_digest
    request.env['HTTP_CONTENT_DIGEST'] = Digest::MD5.hexdigest(body) if body
  end

  def body
    if request.env['rack.input']
      request.env['rack.input'].rewind
      body = request.env['rack.input'].read
      request.env['rack.input'].rewind
      body == '' ? nil : body
    end
  end

  def date
    request.env['HTTP_DATE']
  end

  def set_date
    request.env['HTTP_DATE'] = Time.now.httpdate
  end

  def path
    request.path
  end

  def sign!(key_id, key_secret)
    set_date
    set_content_digest

    request.env['HTTP_X_SIGNATURE_VERSION'] = options[:version] if options[:version]

    request.env["HTTP_#{authorization_header.to_s.upcase}"] = authorization(key_id, key_secret)
  end

  def authorization_signature
    request.env["HTTP_#{authorization_header.to_s.upcase}"]
  end
end
