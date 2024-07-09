# frozen_string_literal: true

RSpec.describe Devicecheck::Data::AuthenticatorData do
  subject do
    described_class.unpack(data)
  end

  let(:rp_id_hash) { SecureRandom.random_bytes(32) }
  let(:flags) { 0 }
  let(:sign_count) { 1 }
  let(:aaguid) { SecureRandom.random_bytes(16) }
  let(:credential_id) { SecureRandom.random_bytes(16) }
  let(:credential_id_length) { [16].pack('n') }
  let(:public_key) { SecureRandom.random_bytes(65) }
  let(:attested_credential_data) { aaguid + credential_id_length + credential_id + public_key }

  let(:data) { rp_id_hash + [flags].pack('c1') + [sign_count].pack('N1') + attested_credential_data }

  it { expect(subject[0]).to eq rp_id_hash }
  it { expect(subject[1]).to eq flags }
  it { expect(subject[2]).to eq sign_count }
  it { expect(subject[3]).to eq aaguid }
  it { expect(subject[4]).to eq credential_id }
  it { expect(subject[5]).to eq public_key }
end
