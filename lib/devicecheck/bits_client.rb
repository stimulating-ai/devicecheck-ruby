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

require 'jwt'
require 'net/http'
require 'json'
require 'time'

module Devicecheck
  # Client for managing DeviceCheck bits (2 bits per device)
  # Handles JWT authentication and API communication with Apple's servers
  class BitsClient
    PRODUCTION_URL = 'https://api.devicecheck.apple.com/v1'.freeze
    DEVELOPMENT_URL = 'https://api.development.devicecheck.apple.com/v1'.freeze

    attr_reader :team_id, :key_id, :private_key, :environment

    # Initialize the DeviceCheck bits client
    #
    # @param team_id [String] Your Apple Developer Team ID
    # @param key_id [String] The key ID from Apple Developer Portal
    # @param private_key [String, OpenSSL::PKey::EC] The private key (PEM string, base64-encoded PEM, or EC key object)
    # @param environment [Symbol] :production or :development
    def initialize(team_id:, key_id:, private_key:, environment: :production)
      @team_id = team_id
      @key_id = key_id
      @private_key = parse_private_key(private_key)
      @environment = environment
    end

    # Query the current bit values for a device
    #
    # @param device_token [String] Base64-encoded device token from the client
    # @param transaction_id [String] Optional unique transaction ID for this request
    # @return [Hash] Response with bit0, bit1, and last_update_time
    def query_bits(device_token:, transaction_id: nil)
      payload = {
        device_token: device_token,
        transaction_id: transaction_id || generate_transaction_id,
        timestamp: (Time.now.to_f * 1000).to_i
      }

      response = make_request('/query_two_bits', payload)
      parse_response(response)
    end

    # Update the bit values for a device
    #
    # @param device_token [String] Base64-encoded device token from the client
    # @param bit0 [Boolean, nil] Value for bit 0 (true/false or nil to leave unchanged)
    # @param bit1 [Boolean, nil] Value for bit 1 (true/false or nil to leave unchanged)
    # @param transaction_id [String] Optional unique transaction ID for this request
    # @return [Hash] Response confirming the update
    def update_bits(device_token:, bit0: nil, bit1: nil, transaction_id: nil)
      payload = {
        device_token: device_token,
        transaction_id: transaction_id || generate_transaction_id,
        timestamp: (Time.now.to_f * 1000).to_i
      }

      # Only include bits that are being set
      payload[:bit0] = bit0 unless bit0.nil?
      payload[:bit1] = bit1 unless bit1.nil?

      response = make_request('/update_two_bits', payload)
      parse_response(response)
    end

    # Validate a device token without querying or updating bits
    #
    # @param device_token [String] Base64-encoded device token from the client
    # @param transaction_id [String] Optional unique transaction ID for this request
    # @return [Hash] Response indicating if the token is valid
    def validate_device_token(device_token:, transaction_id: nil)
      payload = {
        device_token: device_token,
        transaction_id: transaction_id || generate_transaction_id,
        timestamp: (Time.now.to_f * 1000).to_i
      }

      response = make_request('/validate_device_token', payload)
      parse_response(response)
    end

    private

    def parse_private_key(key)
      return key if key.is_a?(OpenSSL::PKey::EC)

      # Try to decode if it looks like base64 (no PEM headers)
      if !key.include?('BEGIN') && !key.include?('END')
        begin
          decoded = Base64.decode64(key)
          # Check if decoded content has PEM headers
          if decoded.include?('BEGIN')
            key = decoded
          end
        rescue => e
          # Not base64 encoded, use as-is
        end
      end

      OpenSSL::PKey::EC.new(key)
    rescue OpenSSL::PKey::ECError => e
      raise ArgumentError, "Invalid private key: #{e.message}"
    end

    def generate_jwt
      headers = {
        alg: 'ES256',
        kid: key_id
      }

      claims = {
        iss: team_id,
        iat: Time.now.to_i,
        exp: Time.now.to_i + 3600 # 1 hour expiry
      }

      JWT.encode(claims, private_key, 'ES256', headers)
    end

    def base_url
      environment == :production ? PRODUCTION_URL : DEVELOPMENT_URL
    end

    def make_request(endpoint, payload)
      uri = URI("#{base_url}#{endpoint}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.read_timeout = 30
      http.open_timeout = 30

      request = Net::HTTP::Post.new(uri.path)
      request['Authorization'] = "Bearer #{generate_jwt}"
      request['Content-Type'] = 'application/json'
      request.body = payload.to_json

      response = http.request(request)

      unless response.is_a?(Net::HTTPSuccess)
        handle_error_response(response)
      end

      response
    end

    def parse_response(response)
      return {} if response.body.nil? || response.body.empty?

      JSON.parse(response.body, symbolize_names: true)
    rescue JSON::ParserError => e
      raise RuntimeError, "Failed to parse response: #{e.message}"
    end

    def handle_error_response(response)
      error_body = JSON.parse(response.body, symbolize_names: true) rescue {}
      error_message = error_body[:message] || response.message

      case response.code.to_i
      when 400
        raise RuntimeError, "Bad Request: #{error_message}"
      when 401
        raise RuntimeError, "Unauthorized: Check your authentication credentials"
      when 403
        raise RuntimeError, "Forbidden: #{error_message}"
      when 404
        raise RuntimeError, "Not Found: Invalid endpoint or resource"
      when 429
        raise RuntimeError, "Rate Limited: Too many requests"
      else
        raise RuntimeError, "Request failed (#{response.code}): #{error_message}"
      end
    end

    def generate_transaction_id
      SecureRandom.uuid
    end
  end
end