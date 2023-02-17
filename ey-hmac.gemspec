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
  gem.homepage      = 'https://github.com/lanej/hmac'

  gem.metadata['bug_tracker_uri'] = "#{gem.homepage}/issues"
  gem.metadata['changelog_uri'] = "#{gem.homepage}/blob/HEAD/CHANGELOG.md"
  gem.metadata['documentation_uri'] = "https://www.rubydoc.info/gems/#{gem.name}/#{gem.version}"
  gem.metadata['homepage_uri'] = gem.homepage
  gem.metadata['source_code_uri'] = "#{gem.homepage}/tree/v#{gem.version}"

  gem.files         = `git ls-files`.split($INPUT_RECORD_SEPARATOR)
  gem.executables   = gem.files.grep(%r{^bin/}).map { |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ['lib']
  gem.license       = 'MIT'

  gem.required_ruby_version = '>= 2.5'

  gem.add_development_dependency 'bundler', '>= 2.2'
  gem.add_development_dependency 'rake'
end
