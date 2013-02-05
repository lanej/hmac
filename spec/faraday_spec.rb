require 'spec_helper'

describe "faraday" do
  before(:all) { Bundler.require(:faraday) }

  let!(:key_id)     { (0...8).map{ 65.+(rand(26)).chr}.join }
  let!(:key_secret) { (0...16).map{ 65.+(rand(26)).chr}.join }
  let!(:adapter)    { Ey::Hmac::Adapter::Faraday }
  let!(:request) do 
    Faraday::Request.new.tap do |r|
      r.method = :get
      r.path = "/auth"
      r.params = {"x" => "1"}
      r.body = "{1: 2}"
      r.headers = {"Content-Type" => "application/xml"}
    end
  end

  it "should sign and read request" do
    Ey::Hmac.sign!(request, key_id, key_secret, adapter: adapter)

    request.headers['Authorization'].should start_with("EyHmac")
    request.headers['Content-Digest'].should == Digest::MD5.hexdigest(request.body)
    Time.parse(request.headers['Date']).should_not be_nil

    yielded = false

    Ey::Hmac.authenticated?(request, adapter: adapter) do |key_id|
      key_id.should == key_id
      yielded = true
      key_secret
    end.should be_true

    yielded.should be_true
  end
end

