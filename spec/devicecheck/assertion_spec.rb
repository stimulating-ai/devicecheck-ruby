# frozen_string_literal: true

RSpec.describe Devicecheck::Assertion do
  subject do
    described_class.new(app_id:, pkey_der: pkey.to_der).assert(
      client_data:,
      client_data_challenge: challenge,
      expected_challenge:,
      assertion_object: assertion,
      count:
    )
  end

  let(:app_id) { 'com.example.foo' }
  let(:pkey) { OpenSSL::PKey::EC.generate('prime256v1') }

  let(:challenge) { SecureRandom.hex }
  let(:client_data) { { foo: 200, challenge: }.to_json }
  let(:expected_challenge) { challenge }

  let(:rp_id_hash) { OpenSSL::Digest.new('SHA256').digest(app_id) }
  let(:flags) { 0 }
  let(:sign_count) { 0 }
  let(:junk) { nil }
  let(:authenticator_data) { [rp_id_hash, flags, sign_count, junk].pack 'a32c1N1a*' }
  let(:nonce) do
    OpenSSL::Digest.new('SHA256').digest(
      authenticator_data + OpenSSL::Digest.new('SHA256').digest(client_data)
    )
  end

  let(:count) { 0 }

  let(:assertion) do
    Base64.strict_encode64(
      {
        signature: pkey.sign(OpenSSL::Digest.new('SHA256'), nonce),
        authenticatorData: authenticator_data
      }.to_cbor
    )
  end

  context 'when data is valid' do
    it { expect { subject }.not_to raise_error }
  end

  context 'when RP ID does not match' do
    let(:rp_id_hash) { OpenSSL::Digest.digest('SHA256', 'some.other.id') }

    it { expect { subject }.to raise_error 'Failed RP ID check' }
  end

  context 'when count is incorrect' do
    let(:count) { 10 }
    let(:sign_count) { 9 }

    it { expect { subject }.to raise_error 'Failed count check' }
  end

  context 'when challenge is incorrect' do
    let(:expected_challenge) { challenge + SecureRandom.hex }

    it { expect { subject }.to raise_error 'Failed challenge check' }
  end
end
