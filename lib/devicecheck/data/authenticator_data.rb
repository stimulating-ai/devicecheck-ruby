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
  module Data
    # Unpacks authenticator data according to the [webauthn specification](https://www.w3.org/TR/webauthn-2/#authenticator-data).
    #
    # ```
    # Authenticator data layout:
    # -------------------------
    #
    # rp_id_hash = 32 bytes
    # flags = 1 byte
    # sign-count = 4 bytes
    # aaguid = 16
    # attestedCredentialData (variable)
    # - aaguid = 16
    #   credentialIdLength(L) = 2
    #   credentialId = L
    #   credentialPublicKey = variable
    # extension (variable)
    # ```
    class AuthenticatorData
      def self.unpack(...) = new.unpack(...)

      def unpack(auth_data)
        (rp_id_hash, flags, sign_count, trailing_bytes) =
          auth_data.unpack('a32c1N1a*')

        (aaguid, credential_id_length, trailing_bytes) =
          trailing_bytes.unpack('a16na*')

        (credential_id, credential_public_key) =
          trailing_bytes.unpack("a#{credential_id_length}a*")

        [rp_id_hash, flags, sign_count, aaguid,
         credential_id, credential_public_key]
      end
    end
  end
end
