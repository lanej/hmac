shared_examples_for "authentication" do
  describe "#authenticated?" do
    it "should not authenticate invalid secret" do
      Ey::Hmac.sign!(request, key_id, "#{key_secret}bad", adapter: adapter)

      expect(Ey::Hmac.authenticated?(request, adapter: adapter) do |auth_id|
        (auth_id == key_id) && key_secret
      end).to be_falsey
    end

    it "should not authenticate invalid id" do
      Ey::Hmac.sign!(request, "what#{key_id}", key_secret, adapter: adapter)

      expect(Ey::Hmac.authenticated?(request, adapter: adapter) do |auth_id|
        (auth_id == key_id) && key_secret
      end).to be_falsey
    end

    it "should not authenticate missing header" do
      expect(Ey::Hmac.authenticated?(request, adapter: adapter) do |auth_id|
        (auth_id == key_id) && key_secret
      end).to be_falsey
    end
  end

  describe "#authenticate!" do
    it "should not authenticate invalid secret" do
      Ey::Hmac.sign!(request, key_id, "#{key_secret}bad", adapter: adapter)

      expect {
        Ey::Hmac.authenticate!(request, adapter: adapter) do |auth_id|
          (auth_id == key_id) && key_secret
        end
      }.to raise_exception(Ey::Hmac::SignatureMismatch)
    end

    it "should not authenticate invalid id" do
      Ey::Hmac.sign!(request, "what#{key_id}", key_secret, adapter: adapter)

      expect {
        Ey::Hmac.authenticate!(request, adapter: adapter) do |auth_id|
          (auth_id == key_id) && key_secret
        end
      }.to raise_exception(Ey::Hmac::MissingSecret)
    end

    it "should not authenticate missing header" do
      expect {
        expect(Ey::Hmac.authenticate!(request, adapter: adapter) do |auth_id|
          (auth_id == key_id) && key_secret
        end).to be_falsey
      }.to raise_exception(Ey::Hmac::MissingAuthorization)
    end

    context "when the server specifies an HMAC TTL" do
      it "should not authenticate expired hmac" do
        Ey::Hmac.sign!(request, key_id, key_secret, adapter: adapter)
        expect {
          Ey::Hmac.authenticate!(request, adapter: adapter, ttl: 0) do |auth_id|
            (auth_id == key_id) && key_secret
          end
        }.to raise_exception(Ey::Hmac::ExpiredHmac)
      end

      it "should authenticate non-expired hmac" do
        Ey::Hmac.sign!(request, key_id, key_secret, adapter: adapter)
        expect {
          Ey::Hmac.authenticate!(request, adapter: adapter, ttl: 100) do |auth_id|
            (auth_id == key_id) && key_secret
          end
        }.to_not raise_exception
      end
    end
  end
end
