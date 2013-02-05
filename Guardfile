guard 'rspec' do
  watch(%r{^spec/.+_spec\.rb$})
  watch(%r{^spec/(shared|support)/.*\.rb$}) { "spec" }
  watch(%r{^lib/(.+)\.rb$})     { "spec" }
  watch('spec/spec_helper.rb')  { "spec" }
end

