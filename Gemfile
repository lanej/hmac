# frozen_string_literal: true

source 'https://rubygems.org'

# Specify your gem's dependencies in ey-hmac.gemspec
gemspec

gem 'rubocop', require: false
gem 'rubocop-rspec', require: false

group(:test) do
  gem 'pry-nav'
  gem 'rspec', '~> 3.3'
end

group(:rack) do
  gem 'rack'
  gem 'rack-client'
  gem 'rack-test'
end

group(:faraday) do
  gem 'faraday', '>= 1.3'
  gem 'faraday_middleware'
end
