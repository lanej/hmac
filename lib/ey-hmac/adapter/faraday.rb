class Ey::Hmac::Adapter::Faraday < Ey::Hmac::Adapter
  def method
    request[:method].to_s.upcase
  end

  def content_type
    %w[CONTENT-TYPE CONTENT_TYPE Content-Type Content_Type].inject(nil) { |r,h| r || request[:request_headers][h] }
  end

  def content_digest
    %w[CONTENT-DIGEST CONTENT_DIGEST Content-Digest Content_Digest].inject(nil) { |r,h| r || request[:request_headers][h] }
  end

  def set_content_digest
    digestable = if body.respond_to?(:rewind)
                   body.rewind
                   body.read.tap { |_| body.rewind }
                 else
                   body.to_s
                 end

    if body && body != ""
      request[:request_headers]['Content-Digest'] = Digest::MD5.hexdigest(digestable)
    end
  end

  def body
    if request[:body] && request[:body].to_s != ""
      request[:body]
    end
  end

  def date
    existing = %w[DATE Date].inject(nil) { |r,h| r || request[h] }
    existing || (request[:request_headers]['Date'] = Time.now.httpdate)
  end

  def path
    request[:url].path
  end

  def sign!(key_id, key_secret)
    map_find(%w[CONTENT-TYPE CONTENT_TYPE Content-Type Content_Type]) { |h| request[:request_headers][h] }

    if options[:version]
      request[:request_headers]['X-Signature-Version'] = options[:version]
    end

    request[:request_headers][authorization_header] = authorization(key_id, key_secret)
  end

  def authorization_signature
    map_find(%w[Authorization AUTHORIZATION]) { |h| request[:request_headers][h] }
  end

  def map_find(keys)
    value = nil
    keys.find { |k|
      value = yield(k)
      break if value
    }
    value
  end
end
