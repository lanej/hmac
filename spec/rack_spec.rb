require 'spec_helper'

describe "rack" do
  before(:all) { Bundler.require(:rack) }

  let!(:key_id)     { (0...8).map{ 65.+(rand(26)).chr}.join }
  let!(:key_secret) { (0...16).map{ 65.+(rand(26)).chr}.join }

  describe "adapter" do
    let(:adapter)     { Ey::Hmac::Adapter::Rack }
    let(:request)     {
      Rack::Request.new({
        "rack.input" => StringIO.new("{1: 2}"),
        "HTTP_CONTENT_TYPE" => "application/json",
      })
    }

    it "should sign and read request" do
      Ey::Hmac.sign!(request, key_id, key_secret, adapter: adapter)

      request.env['HTTP_AUTHORIZATION'].should start_with("EyHmac")
      request.env['HTTP_CONTENT_DIGEST'].should == Digest::MD5.hexdigest(request.body.tap(&:rewind).read)
      request.env['HTTP_SIGNATURE_DIGEST'].should == "SHA256"
      Time.parse(request.env['HTTP_DATE']).should_not be_nil

      yielded = false

      Ey::Hmac.authenticated?(request, adapter: adapter){|public_key| (public_key == key_id) && key_secret }.should be_true
    end

    it "should sign and read request with a specific signature_digest_method" do
      Ey::Hmac.sign!(request, key_id, key_secret, adapter: adapter, signature_digest_method: :sha1)

      request.env['HTTP_AUTHORIZATION'].should start_with("EyHmac")
      request.env['HTTP_CONTENT_DIGEST'].should == Digest::MD5.hexdigest(request.body.tap(&:rewind).read)
      request.env['HTTP_SIGNATURE_DIGEST'].should == "SHA1"
      Time.parse(request.env['HTTP_DATE']).should_not be_nil

      yielded = false

      Ey::Hmac.authenticated?(request, adapter: adapter){|public_key| (public_key == key_id) && key_secret }.should be_true
    end

    include_examples "authentication"
  end

  describe "middleware" do
    it "should sign and read request" do
      app = lambda do |env|
        authenticated = Ey::Hmac.authenticated?(env, adapter: Ey::Hmac::Adapter::Rack) do |auth_id|
          (auth_id == key_id) && key_secret
        end
        [(authenticated ? 200 : 401), {"Content-Type" => "text/plain"}, []]
      end

      _key_id, _key_secret = key_id, key_secret
      client = Rack::Client.new do
        use Ey::Hmac::Rack, _key_id, _key_secret
        run app
      end

      client.get("/resource").status.should == 200
    end
  end
end
