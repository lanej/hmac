class Ey::Hmac::Adapter::Faraday < Ey::Hmac::Adapter
  def method
    request[:method].to_s.upcase
  end

  def content_type
    %w[CONTENT-TYPE CONTENT_TYPE Content-Type Content_Type].inject(nil){|r, h| r || request[h]}
  end

  def content_digest
    existing = %w[CONTENT-DIGEST CONTENT_DIGEST Content-Digest Content_Digest].inject(nil){|r,h| r || request[:request_headers][h]}
    existing || (request[:request_headers]['Content-Digest'] = (body && Digest::MD5.hexdigest(body)))
  end
  
  def body
    if request[:body] && request[:body].to_s != ""
      request[:body]
    else nil
    end
  end

  def date
    existing = %w[DATE Date].inject(nil){|r,h| r || request[h]}
    existing || (request[:request_headers]['Date'] = Time.now.httpdate)
  end

  def path
    request[:url].path
  end

  def sign!(key_id, key_secret)
    %w[CONTENT-TYPE CONTENT_TYPE Content-Type Content_Type].inject(nil){|r,h| request[:request_headers][h]}
    if options[:version]
      request[:request_headers]['X-Signature-Version'] = options[:version]
    end

    request[:request_headers][authorization_header] = authorization(key_id, key_secret)
  end

  def authorization_signature
    %w[Authorization AUTHORIZATION].inject(nil){|r, h| r || request[:request_headers][h]}
  end
end
