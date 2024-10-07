# frozen_string_literal: true

require 'paseto'
require "base64"

class TokenRefreshController < ApplicationController
  raw_key = Rails.application.credentials.dig(:paseto, :secret_key)

  PASETO_SECRET_KEY = Base64.decode64(raw_key) unless raw_key.nil?

  raise "PASETO secret key not set in credentials" unless PASETO_SECRET_KEY.bytesize == 32

  SYMMETRIC_KEY = Paseto::V4::Local.new(ikm: PASETO_SECRET_KEY)

  def refresh
    refresh_token = cookies.signed[:refresh_token]
    debugger
  
    if refresh_token.present?
      begin
        result = SYMMETRIC_KEY.decode(refresh_token)
        payload = result.claims
  
        if Time.at(payload['exp']) > Time.current
          new_access_token = generate_access_token(User.find(payload['sub']))
          render json: {
            status: { 
              code: 200,
              message: 'Token refreshed successfully.',
              token: new_access_token
            }
          }, status: :ok
        else
          render json: {
            status: 401,
            message: "Token expired."
          }, status: :unauthorized
        end
      end
    end
  end
  

  private

  def generate_access_token(current_user)
    payload = {
      sub: current_user.id.to_s,
      exp: 15.minutes.from_now.to_i
    }

    SYMMETRIC_KEY.encode(payload)
  end
end
