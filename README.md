# Logstash Plugin

This is a plugin for [Logstash](https://github.com/elastic/logstash).

It is fully free and fully open source. The license is BSD 3-clause.

## Requirements
* logstash 5.x
* Java Cryptography Extension (JCE)Unlimited Strength Jurisdiction Policy installed (this allows stronger encryption keys than default.)

## Documentation

Logstash provides infrastructure to automatically generate documentation for this plugin. We use the asciidoc format to write documentation so any comments in the source code will be first converted into asciidoc and then into html. All plugin documentation are placed under one [central location](http://www.elastic.co/guide/en/logstash/current/).

- For formatting code or config example, you can use the asciidoc `[source,ruby]` directive
- For more asciidoc formatting tips, see the excellent reference here https://github.com/elastic/docs#asciidoc-guide

## Need Help?

Need help? Try #logstash on freenode IRC or the https://discuss.elastic.co/c/logstash discussion forum.

## Developing

### 1. Plugin Developement and Testing

#### Code
- To get started, you'll need JRuby with the Bundler gem installed..

- Install dependencies
```sh
bundle install
```

#### Test

- Update your dependencies

```sh
bundle install
```

- Run tests

```sh
bundle exec rspec
```

### 2. Running the Plugin in Logstash

#### 2.1 Run in a local Logstash clone

- Edit Logstash `Gemfile` and add the local plugin path:
```ruby
gem "logstash-codec-kms", :path => "/your/local/logstash-codec-kms"
```
- Install plugin
```sh
bin/logstash-plugin install --no-verify
```
- Run Logstash with your plugin
```sh
bin/logstash -e 'input { stdin { codec => kms { key_ids => ["arn:aws:kms:account:region:key/yourkmskey"], codec => "json"}}'
```
At this point any modifications to the plugin code will be applied to this local Logstash setup. After modifying the plugin, simply rerun Logstash.

#### 2.2 Run in an installed Logstash

You can use the same **2.1** method to run your plugin in an installed Logstash by editing its `Gemfile` and pointing the `:path` to your local plugin development directory or you can build the gem and install it using:

- Build your plugin gem
```sh
gem build logstash-codec-kms.gemspec
```
- Install the plugin from the Logstash home
```sh
bin/logstash-plugin install /your/local/plugin/logstash-codec-kms.gem
```
- Start Logstash and proceed to test the plugin

## Contributing

All contributions are welcome: ideas, patches, documentation, bug reports, complaints, and even something you drew up on a napkin.

Programming is not a required skill. Whatever you've seen about open source and maintainers or community members  saying "send patches or die" - you will not see that here.

It is more important to the community that you are able to contribute.

For more information about contributing, see the [CONTRIBUTING](https://github.com/elastic/logstash/blob/master/CONTRIBUTING.md) file.
