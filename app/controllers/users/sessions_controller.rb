# frozen_string_literal: true
require "paseto"
require "base64"

class Users::SessionsController < Devise::SessionsController
  raw_key = Rails.application.credentials.dig(:paseto, :secret_key)

  PASETO_SECRET_KEY = Base64.decode64(raw_key) unless raw_key.nil?

  raise "PASETO secret key not set in credentials" unless PASETO_SECRET_KEY.bytesize == 32

  SYMMETRIC_KEY = Paseto::V4::Local.new(ikm: PASETO_SECRET_KEY)

  respond_to :json

  private

  def respond_with(current_user, _opts = {})
    paseto_token = generate_paseto_token(current_user)
    Rails.logger.debug "Generated Token: #{paseto_token}"
    render json: {
      status: { 
        code: 200, message: 'Logged in successfully.',
        token: paseto_token,
        data: { user: UserSerializer.new(current_user).serializable_hash[:data][:attributes] }
      }
    }, status: :ok
  end

  def respond_to_on_destroy
    paseto_token = request.headers['Authorization']&.split(' ')&.last
    current_user = nil
  
    if paseto_token.present?
      begin
        result = SYMMETRIC_KEY.decode(paseto_token)
        payload = result.claims
  
        current_user = User.find(payload['user_id'])
      rescue StandardError => e
        Rails.logger.warn "Error processing PASETO token: #{e.message}"
      end
    end
  
    if current_user
      render json: {
        status: 200,
        message: 'Logged out successfully.'
      }, status: :ok
    else
      render json: {
        status: 401,
        message: "Couldn't find an active session."
      }, status: :unauthorized
    end
  end

  def generate_paseto_token(current_user)
    payload = {
      sub: current_user.id.to_s,
      exp: 24.hours.from_now.to_i
    }

    SYMMETRIC_KEY.encode(payload)
  end
end
