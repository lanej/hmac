source 'https://rubygems.org'

# Specify your gem's dependencies in ey-hmac.gemspec
gemspec

group(:test) do
  gem 'guard-bundler'
  gem 'guard-rspec', '~> 4.2'
  gem 'pry-nav'
  gem 'rspec', '~> 2.99'
end

group(:rack) do
  gem 'rack'
  gem 'rack-test'
  gem 'rack-client'
end

group(:faraday) do
  gem 'faraday'
  gem 'faraday_middleware', "~> 0.9.0"
end
