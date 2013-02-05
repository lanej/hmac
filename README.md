# Ey::Hmac

Lightweight libraries and middlewares to perform HMAC signing and verification

## Installation

Add this line to your application's Gemfile:

    gem 'ey-hmac'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ey-hmac

## Documentation

  [rdoc.info](http://rubydoc.info/gems/ey-hmac)

## Usage

## Client Middleware

### Rack

Using ```Rack::Client```

```ruby
client = Rack::Client.new do
  use Ey::Hmac::Rack, key_id, key_secret
  run app
end
```

### Faraday

```ruby
require 'ey-hmac/faraday'

connection = Faraday.new do |c|
  c.request :hmac, key_id, key_secret
  c.adapter(:rack, app)
end
```

## Server

### Rack

```ruby
app = lambda do |env|
  authenticated = Ey::Hmac.authenticated?(env, adapter: Ey::Hmac::Adapter::Rack) do |auth_id|
    (auth_id == key_id) && key_secret
  end
  [(authenticated ? 200 : 401), {"Content-Type" => "text/plain"}, []]
end

```

### Rails

```ruby
Ey::Hmac.authenticated?(request.env) do |auth_id|
  if consumer_credential = ConsumerCredential.where(deleted_at: nil, auth_id: auth_id).first
    consumer = consumer_credential.try(:consumer)
    consumer && consumer.enabled && consumer_credential.auth_key
  end
end && consumer
```


## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
