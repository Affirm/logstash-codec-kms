# encoding: utf-8
require "logstash/codecs/base"
require "logstash/namespace"
require "logstash-codec-kms_jars"
require "logstash/util/charset"
require "logstash/errors"

# A codec to encrypt/decrypt messages using AWS KMS
#
# This plugin uses the AWS Encryption SDK vended by Amazon.
# See http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html for the details.
#
# To use this plugin, you *must*:
#
#  * Have an AWS account.
#  * Setup a KMS key to use.
#  * Create an identity that has access to decrypt using the kms key you created.
#
# See https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html
# for details on creating keys.
#
# See http://docs.aws.amazon.com/kms/latest/developerguide/control-access-overview.html#managing-access
# for details on seting up permissions for AWS KMS.
#
class LogStash::Codecs::Kms < LogStash::Codecs::Base

  config_name "kms"

  # The codec used after the message is decrypted (if this is used with an input)
  # or the codec to use before the message is encrypted (if this is used with an output)
  # [source,ruby]
  #     stdin {
  #         codec => kms {
  #             codec => "json"
  #         }
  #     }
  #
  config :codec, :validate => :codec, :default => "plain"

  # A list of KMS key ids. If more than one key is provided, the encrypted payload will
  # contain a copy of the data key encrypted with each of the keys specified here.
  # At minimum, you should provide a single key id to use for KMS encryption.
  config :key_ids, :validate => :string, :list => true, :required => true

  # The AWS region for KMS (ex us-east-1)
  config :region, :validate => :string, :required => true

  # An optional aws access key id to use for AWS. If omitted, the regular default locations are checked on the system
  # See http://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html
  config :access_key, :validate => :string, :default => nil

  # An optional secret access key to use for AWS. If omitted, the regular default locations are checked on the system
  # See http://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html
  config :secret_key, :validate => :string, :default => nil

  # An optional AWS profile to use.
  # See http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-multiple-profiles
  config :aws_profile, :validate => :string, :default => nil

  # An encryption context to use to encrypting and decrypting data.
  # When encrypting, the encryption context is sent as a part of the payload.
  # When decrypting, if any of the key-value pairs specified in encryption_context
  # fails to match the payload's encryption context, then decryption will fail.
  # Nested hashes are not supported. This is just a flat map of key value pairs.
  # See: http://docs.aws.amazon.com/kms/latest/developerguide/encryption-context.html
  config :encryption_context, :validate => :hash, :default => {}

  # If set, incoming messages that cannot be decrypted will try to pass the original message
  # through this plugin's codec. By default, undecryptable messages will fail immediately.

  # This is useful to avoid issues while you are migrating to an encrypted transport.
  # For example, if you are currently sending unencrypted data, but want to start sending KMS encrypted data,
  # there will be a window during your deployment where old hosts are sending plain data while new hosts
  # are sending encrypted data.
  # You can handle this case by setting fallback_if_invalid_format to true.
  #
  # The following example will pass messages that fail to be decrypted through the json codec.
  # [source,ruby]
  #     stdin {
  #         codec => kms {
  #             codec => "json"
  #             fallback_if_invalid_format => true
  #         }
  #     }
  #
  config :fallback_if_invalid_format, :validate => :boolean, :default => false

  # The expected charset of the data AFTER decryption.
  config :charset, :validate => ::Encoding.name_list, :default => "UTF-8"

  # The TTL of entries in the KMS materials cache.
  config :max_entry_age_ms, :validate => :number, :default => 300000

  # The maximum number of times a caches KMS material can be used before it is refreshed.
  config :max_entry_uses, :validate => :number, :default => 1000

  # The capacity for the KMS materials cache.
  config :max_cache_entries, :validate => :number, :default => 1000

  attr_reader :crypto_client
  attr_reader :crypto_materials_manager

  def register
    @encryption_context.each do |key, value|
      if not value.is_a?(String)
        raise LogStash::ConfigurationError.new("Values in encryption_context must be strings.")
      end
    end

    @crypto_client = com.amazonaws.encryptionsdk::AwsCrypto.new

    credentials = com.amazonaws.auth::DefaultAWSCredentialsProviderChain.new
    if @access_key and @access_key
      credentials = com.amazonaws.auth::AWSStaticCredentialsProvider.new(
        com.amazonaws.auth::BasicAWSCredentials.new(
          @access_key,
          @secret_key
        )
      )
      @logger.debug("Using AWSStaticCredentialsProvider", plugin: self.class.name)
    elsif @aws_profile
      credentials = com.amazonaws.auth.profile::ProfileCredentialsProvider.new(@aws_profile)
      @logger.debug("Using ProfileCredentialsProvider", plugin: self.class.name)
    end

    key_provider = com.amazonaws.encryptionsdk.kms::KmsMasterKeyProvider.new(
      credentials,
      com.amazonaws.regions::RegionUtils::getRegion(@region),
      com.amazonaws::ClientConfiguration.new,
      @key_ids
    )

    @crypto_materials_manager = com.amazonaws.encryptionsdk.caching::CachingCryptoMaterialsManager.newBuilder()
      .withMasterKeyProvider(key_provider)
      .withCache(com.amazonaws.encryptionsdk.caching::LocalCryptoMaterialsCache.new(@max_cache_entries))
      .withMaxAge(@max_entry_age_ms, java.util.concurrent.TimeUnit::MILLISECONDS)
      .withMessageUseLimit(@max_entry_uses)
      .build()

    @logger.debug("Encryption Context: " + @encryption_context.to_s, plugin: self.class.name)
  end # def register

  def decode(data)
    begin
      response = self.crypto_client.decryptData(@crypto_materials_manager, data.to_java_bytes)
      context = response.getEncryptionContext()
      @encryption_context.each do |key, value|
        if not context.containsKey(key) or context[key] != value
          raise RuntimeError.new('Encryption context does not match expected. Recieved context: ' + context.to_s)
        end
      end
      data = String.from_java_bytes(response.getResult(), @charset)
    rescue com.amazonaws.encryptionsdk.exception::AwsCryptoException
      raise unless @fallback_if_invalid_format
    end

    @codec.decode(data, &Proc.new)
  end # def decode

  # Encode a single event, this returns the raw data to be returned as a String
  def encode_sync(event)
    data = @codec.multi_encode([event])[0][1]
    encrypted = self.crypto_client.encryptData(@crypto_materials_manager, data.to_java_bytes, @encryption_context).getResult()
    return String.from_java_bytes(encrypted, 'BINARY')
  end # def encode_sync
end # class LogStash::Codecs::Kms
