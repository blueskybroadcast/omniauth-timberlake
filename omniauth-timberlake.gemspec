# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth-timberlake/version'

Gem::Specification.new do |spec|
  spec.name          = "omniauth-timberlake"
  spec.version       = Omniauth::Timberlake::VERSION
  spec.authors       = ["Dave Sloan"]
  spec.email         = ["dsloan@blueskybroadcast.com"]
  spec.summary       = %q{TIMBERLAKE SSO}
  spec.description   = %q{TIMBERLAKE SSO}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency 'omniauth', '~> 1.0'
  spec.add_dependency 'omniauth-oauth2', '~> 1.0'
  spec.add_dependency 'rest-client'

  spec.add_development_dependency "bundler", "~> 1.6"
  spec.add_development_dependency "rake"
end
