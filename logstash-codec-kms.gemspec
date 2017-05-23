Gem::Specification.new do |s|
  s.name          = 'logstash-codec-kms'
  s.version       = '0.1.0'
  s.licenses      = ['BSD-3-Clause']
  s.summary       = "Codec for decrypting and encrypting messages using AWS KMS in Logstash"
  s.description   = "This gem is a logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program"
  s.authors       = ["Greg Sterin"]
  s.email         = 'gmsterin@hotmail.com'
  s.homepage      = "http://www.elastic.co/guide/en/logstash/current/index.html"
  s.require_paths = ["lib"]
  s.platform = "java"

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "codec" }

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core-plugin-api', "~> 2.0"
  s.add_runtime_dependency 'logstash-codec-line'
  s.add_runtime_dependency 'logstash-codec-plain'
  s.add_runtime_dependency 'logstash-codec-json'
  s.add_development_dependency 'logstash-devutils'

  s.requirements << "jar 'com.amazonaws:aws-encryption-sdk-java', '0.0.1'"
  s.requirements << "jar 'com.amazonaws:aws-java-sdk', '1.11.118'"
  s.add_runtime_dependency 'jar-dependencies'
end
