class Ey::Hmac::Adapter::Faraday < Ey::Hmac::Adapter
  def method
    request.method
  end

  def content_type
    %w[CONTENT-TYPE CONTENT_TYPE Content-Type Content_Type].inject(nil){|r, h| r || request[h]}
  end

  def content_digest
    existing = %w[CONTENT-DIGEST CONTENT_DIGEST Content-Digest Content_Digest].inject(nil){|r,h| r || request[h]}
    existing || (request['Content-Digest'] = (body && Digest::MD5.hexdigest(body)))
  end
  
  def body
    request.body
  end

  def date
    existing = %w[DATE Date].inject(nil){|r,h| r || request[h]}
    existing || (request['Date'] = Time.now.httpdate)
  end

  def path
    request.path
  end

  def sign!(key_id, key_secret)
    %w[CONTENT-TYPE CONTENT_TYPE Content-Type Content_Type].inject(nil){|r,h| request[h]}
    if options[:version]
      request.headers['X-Signature-Version'] = options[:version]
    end

    request.headers[authorization_header] = authorization(key_id, key_secret)
  end

  def authorization_signature
    %w[Authorization AUTHORIZATION].inject(nil){|r, h| r || request.headers[h]}
  end
end
