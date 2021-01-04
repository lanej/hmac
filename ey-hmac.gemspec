# -*- encoding: utf-8 -*-
require File.expand_path('../lib/ey-hmac/version', __FILE__)

Gem::Specification.new do |gem|
  gem.name          = "ey-hmac"
  gem.version       = Ey::Hmac::VERSION
  gem.authors       = ["Josh Lane", "Jason Hansen"]
  gem.email         = ["jlane@engineyard.com"]
  gem.description   = %q{Lightweight HMAC signing libraries and middleware for Farday and Rack}
  gem.summary       = %q{Lightweight HMAC signing libraries and middleware for Farday and Rack}
  gem.homepage      = ""

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]
  gem.license       = "MIT"

  gem.add_development_dependency "rake"
  gem.add_development_dependency "bundler", "~> 2.0"
end
