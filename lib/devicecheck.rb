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

require 'openssl'
require 'base64'
require 'cbor'

require_relative 'devicecheck/version'
require_relative 'devicecheck/data/authenticator_data'
require_relative 'devicecheck/validators/certificate_chain_validator'
require_relative 'devicecheck/attestation'
require_relative 'devicecheck/assertion'

# {include:file:README.md}
module Devicecheck
end
