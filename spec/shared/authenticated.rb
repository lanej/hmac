shared_examples_for "authentication" do
  describe "#authenticated?" do
    it "should not authenticate invalid secret" do
      Ey::Hmac.sign!(request, key_id, "#{key_secret}bad", adapter: adapter)

      Ey::Hmac.authenticated?(request, adapter: adapter) do |auth_id|
        (auth_id == key_id) && key_secret
      end.should be_false
    end

    it "should not authenticate invalid id" do
      Ey::Hmac.sign!(request, "what#{key_id}", key_secret, adapter: adapter)

      Ey::Hmac.authenticated?(request, adapter: adapter) do |auth_id|
        (auth_id == key_id) && key_secret
      end.should be_false
    end

    it "should not authenticate missing header" do
      Ey::Hmac.authenticated?(request, adapter: adapter) do |auth_id|
        (auth_id == key_id) && key_secret
      end.should be_false
    end
  end

  describe "#authenticate!" do
    it "should not authenticate invalid secret" do
      Ey::Hmac.sign!(request, key_id, "#{key_secret}bad", adapter: adapter)

      lambda {
        Ey::Hmac.authenticate!(request, adapter: adapter) do |auth_id|
          (auth_id == key_id) && key_secret
        end
      }.should raise_exception(Ey::Hmac::SignatureMismatch)
    end

    it "should not authenticate invalid id" do
      Ey::Hmac.sign!(request, "what#{key_id}", key_secret, adapter: adapter)

      lambda {
        Ey::Hmac.authenticate!(request, adapter: adapter) do |auth_id|
          (auth_id == key_id) && key_secret
        end
      }.should raise_exception(Ey::Hmac::MissingSecret)
    end

    it "should not authenticate missing header" do
      lambda {
        Ey::Hmac.authenticate!(request, adapter: adapter) do |auth_id|
          (auth_id == key_id) && key_secret
        end.should be_false
      }.should raise_exception(Ey::Hmac::MissingAuthorization)
    end
  end
end
