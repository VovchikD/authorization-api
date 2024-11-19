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
    access_token = generate_access_token(current_user)
    refresh_token = generate_refresh_token(current_user)

    cookies.signed[:refresh_token] = {
      value: refresh_token,
      httponly: true,
      expires: 24.hours.from_now,
    }

    render json: {
      status: { 
        code: 200,
        message: 'Logged in successfully.',
        token: access_token,
        data: { user: UserSerializer.new(current_user).serializable_hash.json }
      }
    }, status: :ok
  end

  def respond_to_on_destroy
    cookies.delete(:refresh_token)

    render json: {
      status: 200,
      message: 'Logged out successfully.'
    }, status: :ok
  end

  def generate_access_token(current_user)
    payload = {
      sub: current_user.id.to_s,
      exp: 15.minutes.from_now.to_i
    }

    SYMMETRIC_KEY.encode(payload)
  end

  def generate_refresh_token(current_user)
    payload = {
      sub: current_user.id.to_s,
      exp: 24.hours.from_now.to_i
    }

    SYMMETRIC_KEY.encode(payload)
  end
end

