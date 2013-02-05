require 'spec_helper'

describe "Rack" do
  let!(:key_id) { (0...8).map{65.+(rand(26)).chr}.join }
  let!(:key_secret) { (0...16).map{65.+(rand(26)).chr}.join }
  let(:request) { Rack::Request.new({}) }
  let(:adapter) { Ey::Hmac::Signer::Rack }

  it "should sign and read request" do
    Ey::Hmac.sign!(request, key_id, key_secret, signer: adapter)

    request.env['HTTP_AUTHORIZATION'].should start_with("EyHmac")

    yielded = false

    Ey::Hmac.authenticated?(request, reader: adapter) do |key_id|
      key_id.should == key_id
      yielded = true
      key_secret
    end.should be_true

    yielded.should be_true
  end
end
