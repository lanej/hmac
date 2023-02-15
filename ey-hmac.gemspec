# frozen_string_literal: true

require 'English'
require File.expand_path('lib/ey-hmac/version', __dir__)

Gem::Specification.new do |gem|
  gem.name          = 'ey-hmac'
  gem.version       = Ey::Hmac::VERSION
  gem.authors       = ['Josh Lane']
  gem.email         = ['me@joshualane.com']
  gem.description   = 'Lightweight HMAC signing libraries and middleware for Farday and Rack'
  gem.summary       = 'Lightweight HMAC signing libraries and middleware for Farday and Rack'
  gem.homepage      = ''

  gem.files         = `git ls-files`.split($INPUT_RECORD_SEPARATOR)
  gem.executables   = gem.files.grep(%r{^bin/}).map { |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ['lib']
  gem.license       = 'MIT'

  gem.required_ruby_version = '>= 2.5'

  gem.add_development_dependency 'bundler', '>= 2.2'
  gem.add_development_dependency 'rake'
end
