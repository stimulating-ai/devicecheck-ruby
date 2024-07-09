# frozen_string_literal: true

# Copyright 2024 Catawiki B.V.
#
# Licensed under the MIT License (the "License");
#
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at
#
#     https://opensource.org/licenses/MIT
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

module Devicecheck
  module Validators
    # Verifies that the x5c array contains the intermediate and leaf
    # certificates for App Attest, starting from the credential
    # certificate in the first data buffer in the array
    # (credcert). Uses Apple’s [App Attest root
    # certificate](https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem).
    class CertificateChainValidator
      ROOT_CA =
        OpenSSL::X509::Certificate.new(<<~PEM)
          -----BEGIN CERTIFICATE-----
          MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
          JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
          QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
          Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
          biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
          bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
          NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
          Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
          MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
          CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
          53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
          oyFraWVIyd/dganmrduC1bmTBGwD
          -----END CERTIFICATE-----
        PEM

      def self.validate(...) = new.validate(...)

      def initialize(root_ca: ROOT_CA)
        @certificates_store = OpenSSL::X509::Store.new.add_cert(root_ca)
      end

      def validate(att_stmt)
        certificates =
          att_stmt['x5c'].map { |c| OpenSSL::X509::Certificate.new(c) }

        cred_cert, *certificate_chain = certificates

        store_context = OpenSSL::X509::StoreContext.new(
          certificates_store, cred_cert, certificate_chain
        )

        cred_cert if store_context.verify
      end

      private

      attr_reader :certificates_store
    end
  end
end
