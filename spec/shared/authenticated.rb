# frozen_string_literal: true

shared_examples_for 'authentication' do
  describe '#authenticated?' do
    it 'does not authenticate invalid secret' do
      Ey::Hmac.sign!(request, key_id, "#{key_secret}bad", adapter: adapter)

      expect(Ey::Hmac).not_to be_authenticated(request, adapter: adapter) do |auth_id|
        (auth_id == key_id) && key_secret
      end
    end

    it 'does not authenticate invalid id' do
      Ey::Hmac.sign!(request, "what#{key_id}", key_secret, adapter: adapter)

      expect(Ey::Hmac).not_to be_authenticated(request, adapter: adapter) do |auth_id|
        (auth_id == key_id) && key_secret
      end
    end

    it 'does not authenticate missing header' do
      expect(Ey::Hmac).not_to be_authenticated(request, adapter: adapter) do |auth_id|
        (auth_id == key_id) && key_secret
      end
    end
  end

  describe '#authenticate!' do
    it 'does not authenticate invalid secret' do
      Ey::Hmac.sign!(request, key_id, "#{key_secret}bad", adapter: adapter)

      expect do
        Ey::Hmac.authenticate!(request, adapter: adapter) do |auth_id|
          (auth_id == key_id) && key_secret
        end
      end.to raise_exception(Ey::Hmac::SignatureMismatch)
    end

    it 'does not authenticate invalid id' do
      Ey::Hmac.sign!(request, "what#{key_id}", key_secret, adapter: adapter)

      expect do
        Ey::Hmac.authenticate!(request, adapter: adapter) do |auth_id|
          (auth_id == key_id) && key_secret
        end
      end.to raise_exception(Ey::Hmac::MissingSecret)
    end

    it 'does not authenticate missing header' do
      expect do
        expect(Ey::Hmac.authenticate!(request, adapter: adapter) do |auth_id|
          (auth_id == key_id) && key_secret
        end).to be_falsey
      end.to raise_exception(Ey::Hmac::MissingAuthorization)
    end

    context 'when the server specifies an HMAC TTL' do
      it 'does not authenticate expired hmac' do
        Ey::Hmac.sign!(request, key_id, key_secret, adapter: adapter)
        expect do
          Ey::Hmac.authenticate!(request, adapter: adapter, ttl: 0) do |auth_id|
            (auth_id == key_id) && key_secret
          end
        end.to raise_exception(Ey::Hmac::ExpiredHmac)
      end

      it 'authenticates non-expired hmac' do
        Ey::Hmac.sign!(request, key_id, key_secret, adapter: adapter)
        expect do
          Ey::Hmac.authenticate!(request, adapter: adapter, ttl: 100) do |auth_id|
            (auth_id == key_id) && key_secret
          end
        end.not_to raise_exception
      end
    end
  end
end
