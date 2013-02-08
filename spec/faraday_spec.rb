require 'spec_helper'

describe "faraday" do
  before(:all) { Bundler.require(:faraday) }
  let!(:key_id)     { (0...8).map{ 65.+(rand(26)).chr}.join }
  let!(:key_secret) { (0...16).map{ 65.+(rand(26)).chr}.join }

  describe "adapter" do
    let!(:adapter)    { Ey::Hmac::Adapter::Faraday }
    let!(:request) do
      Faraday::Request.new.tap do |r|
        r.method = :get
        r.path = "/auth"
        r.body = "{1: 2}"
        r.headers = {"Content-Type" => "application/xml"}
      end.to_env(Faraday::Connection.new("http://localhost"))
    end

    it "should sign and read request" do
      Ey::Hmac.sign!(request, key_id, key_secret, adapter: adapter)

      request[:request_headers]['Authorization'].should start_with("EyHmac")
      request[:request_headers]['Content-Digest'].should == Digest::MD5.hexdigest(request[:body])
      request[:request_headers]['Signature-Digest'].should == "SHA256"
      Time.parse(request[:request_headers]['Date']).should_not be_nil

      yielded = false

      Ey::Hmac.authenticated?(request, adapter: adapter){|public_key| (public_key == key_id) && key_secret }.should be_true
    end

    it "should sign and read request with a specific signature_digest_method" do
      Ey::Hmac.sign!(request, key_id, key_secret, adapter: adapter, signature_digest_method: :sha1)

      request[:request_headers]['Authorization'].should start_with("EyHmac")
      request[:request_headers]['Content-Digest'].should == Digest::MD5.hexdigest(request[:body])
      request[:request_headers]['Signature-Digest'].should == "SHA1"
      Time.parse(request[:request_headers]['Date']).should_not be_nil

      yielded = false

      Ey::Hmac.authenticated?(request, adapter: adapter){|public_key| (public_key == key_id) && key_secret }.should be_true
    end

    include_examples "authentication"
  end

  describe "middleware" do
    it "should sign request" do
      require 'ey-hmac/faraday'
      Bundler.require(:rack)

      app = lambda do |env|
        authenticated = Ey::Hmac.authenticated?(env, adapter: Ey::Hmac::Adapter::Rack) do |auth_id|
          (auth_id == key_id) && key_secret
        end
        [(authenticated ? 200 : 401), {"Content-Type" => "text/plain"}, []]
      end

      request_env = nil
      connection = Faraday.new do |c|
        c.request :hmac, key_id, key_secret
        c.adapter(:rack, app)
      end

      connection.get("/resources").status.should == 200
    end
  end
end
