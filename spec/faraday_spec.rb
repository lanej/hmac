require 'spec_helper'

describe "faraday" do
  before(:all) { Bundler.require(:faraday) }

  let!(:key_id)     { (0...8).map{ 65.+(rand(26)).chr}.join }
  let!(:key_secret) { (0...16).map{ 65.+(rand(26)).chr}.join }
  let!(:adapter)    { Ey::Hmac::Signer::Faraday }
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
    Ey::Hmac.sign!(request, key_id, key_secret, signer: adapter)

    request.headers['Authorization'].should start_with("EyHmac")

    yielded = false

    Ey::Hmac.authenticated?(request, reader: adapter) do |key_id|
      key_id.should == key_id
      yielded = true
      key_secret
    end.should be_true

    yielded.should be_true
  end
end

