require 'spec_helper'


describe "rack" do
  before(:all) { Bundler.require(:rack) }

  let!(:key_id)     { (0...8).map{ 65.+(rand(26)).chr}.join }
  let!(:key_secret) { (0...16).map{ 65.+(rand(26)).chr}.join }
  let(:adapter)     { Ey::Hmac::Signer::Rack }
  let(:request)     {
    Rack::Request.new({
      "rack.input" => StringIO.new("{1: 2}"),
      "HTTP_CONTENT_TYPE" => "application/json",
    })
  }

  it "should sign and read request" do
    Ey::Hmac.sign!(request, key_id, key_secret, signer: adapter)

    request.env['HTTP_AUTHORIZATION'].should start_with("EyHmac")
    request.env['HTTP_CONTENT_DIGEST'].should == Digest::MD5.hexdigest(request.body.tap(&:rewind).read)
    Time.parse(request.env['HTTP_DATE']).should_not be_nil

    yielded = false

    Ey::Hmac.authenticated?(request, reader: adapter) do |key_id|
      key_id.should == key_id
      yielded = true
      key_secret
    end.should be_true

    yielded.should be_true
  end
end
