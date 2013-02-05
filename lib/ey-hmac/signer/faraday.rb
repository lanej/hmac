class Ey::Hmac::Signer::Faraday < Ey::Hmac::Signer
  def request_method
    request.method
  end

  def content_type
    %w[CONTENT-TYPE CONTENT_TYPE Content-Type Content_Type].inject(nil){|r, h| r || request[h]}
  end

  def content_md5
    existing = %w[CONTENT-MD5 CONTENT_MD5 Content-MD5 Content_MD5].inject(nil){|r,h| r || request[h]}
    existing ||= (request['Content-MD5'] = body && Digest::MD5.hexdigest(body))
  end
  
  def body
    request[:body]
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
