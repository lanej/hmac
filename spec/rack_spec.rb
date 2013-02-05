require 'spec_helper'

describe "Ey::Hmac::Signer" do
  let!(:key_id) { (0...8).map{65.+(rand(26)).chr}.join }
  let!(:key_secret) { (0...16).map{65.+(rand(26)).chr}.join }

  context "Rack" do
    let(:request) { Rack::Request.new({}) }
    let(:signer) { Ey::Hmac::Signer::Rack }

    it "should sign" do
      Ey::Hmac.sign!(request, key_id, key_secret, signer: signer)
    end
  end
end
