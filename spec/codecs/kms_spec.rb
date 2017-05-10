# encoding: utf-8
require_relative '../spec_helper'
require "logstash/codecs/kms"
require "logstash/event"
require "logstash/codecs/plain"

RSpec.describe "codecs/kms" do
  let(:config) {{
    "key_ids" => "testkey",
    "region" => "us-east-1",
    "encryption_context" => {
        "foo" => "bar"
    }
  }}

  subject!(:kms) { LogStash::Codecs::Kms.new(config) }

  let(:mock_encrypt_result) { double('encrypt_result', :getResult => 'encrypted'.to_java_bytes)}
  let(:mock_decrypt_result) { 
    double('decrypt_result',
           :getResult => 'decrypted'.to_java_bytes, 
           :getEncryptionContext => Java::JavaUtil::HashMap.new(config["encryption_context"]))
  }
  let(:mock_client) { 
    double(
      'crypto_client',
      :encryptData => mock_encrypt_result,
      :decryptData => mock_decrypt_result) 
  }

  context "encryption_context matches" do
    it "registers without error" do
        codec = LogStash::Plugin.lookup("codec", "kms").new(config)
        expect { codec.register }.to_not raise_error
    end

    it "registers with aws keys without error" do
        codec = LogStash::Plugin.lookup("codec", "kms").new(config.merge({"access_key" => "foo", "secret_key" => "bar" }))
        expect { codec.register }.to_not raise_error
    end

    it "registers with aws profile without error" do
        codec = LogStash::Plugin.lookup("codec", "kms").new(config.merge({"aws_profile" => "foo" }))
        expect { codec.register }.to_not raise_error
    end

    it "decrypts" do
        expect(kms).to receive(:get_crypto_client).and_return(mock_client)
        event = nil
        kms.decode("some_data") do |decoded|
            event = decoded
        end
        expect(event.get("message")).to eql('decrypted')
    end

    it "encrypts" do
        expect(kms).to receive(:get_crypto_client).and_return(mock_client)
        event = LogStash::Event.new
        event.set("message", "Hello World.")
        data = kms.encode_sync(event)
        expect(data).to eql('encrypted')
    end

    it "decrypt fails with passthrough" do
        codec = LogStash::Plugin.lookup("codec", "kms").new(config.merge("fallback_if_invalid_format" => true))
        expect(codec).to receive(:get_crypto_client).and_return(mock_client)
        allow(mock_client).to receive(:decryptData).and_raise(
            com.amazonaws.encryptionsdk.exception::AwsCryptoException.new())
        event = nil
        codec.decode("some_data") do |decoded|
            event = decoded
        end
        expect(event.get("message")).to eql('some_data')
    end

    it "decrypt fails without passthrough" do
        exception = com.amazonaws.encryptionsdk.exception::AwsCryptoException.new()
        expect(kms).to receive(:get_crypto_client).and_return(mock_client)
        allow(mock_client).to receive(:decryptData).and_raise(exception)
        expect { kms.decode("some_data") }.to raise_error(exception)
    end
  end

  context "encryption_context doesn't match'" do
    let(:mock_decrypt_result) { 
      double('decrypt_result',
             :getResult => 'decrypted'.to_java_bytes, 
             :getEncryptionContext => Java::JavaUtil::HashMap.new({"wrong" => "context"}))
    }

    it "decrypts" do
        expect(kms).to receive(:get_crypto_client).and_return(mock_client)
        expect { kms.decode("some_data")  }.to raise_error(RuntimeError)
    end
  end
end
