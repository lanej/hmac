# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ey-hmac/version'

Gem::Specification.new do |gem|
  gem.name          = "ey-hmac"
  gem.version       = Ey::Hmac::VERSION
  gem.authors       = ["Josh Lane & Jason Hansen"]
  gem.email         = ["jlane@engineyard.com"]
  gem.description   = %q{Lightweight HMAC signing libraries and middleware for Farday and Rack}
  gem.summary       = %q{Lightweight HMAC signing libraries and middleware for Farday and Rack}
  gem.homepage      = ""

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.add_development_dependency "rake"
  gem.add_development_dependency "bundler", "~> 1.3"
end
