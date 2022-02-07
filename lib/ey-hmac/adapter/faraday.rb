# frozen_string_literal: true

class Ey::Hmac::Adapter::Faraday < Ey::Hmac::Adapter
  def method
    request[:method].to_s.upcase
  end

  def content_type
    @content_type ||= find_header(
      'CONTENT-TYPE', 'CONTENT_TYPE', 'Content-Type', 'Content_Type'
    )
  end

  def content_digest
    @content_digest ||= find_header(
      'CONTENT-DIGEST', 'CONTENT_DIGEST', 'Content-Digest', 'Content_Digest'
    )
  end

  def set_content_digest
    return if content_digest

    digestable = if body.respond_to?(:rewind)
                   body.rewind
                   body.read.tap { |_| body.rewind }
                 else
                   body.to_s
                 end

    if digestable && digestable != ''
      @content_digest = request[:request_headers]['Content-Digest'] = Digest::MD5.hexdigest(digestable)
    end
  end

  def body
    request[:body] if request[:body] && request[:body].to_s != ''
  end

  def date
    find_header('DATE', 'Date')
  end

  def set_date
    request[:request_headers]['Date'] = Time.now.httpdate unless date
  end

  def path
    request[:url].path
  end

  def sign!(key_id, key_secret)
    set_content_digest
    set_date

    request[:request_headers]['X-Signature-Version'] = options[:version] if options[:version]

    request[:request_headers][authorization_header] = authorization(key_id, key_secret)
  end

  def authorization_signature
    find_header('Authorization', 'AUTHORIZATION')
  end

  private

  def find_header(*keys)
    value = nil
    keys.find { |k| value = request[:request_headers][k] }
    value
  end
end
