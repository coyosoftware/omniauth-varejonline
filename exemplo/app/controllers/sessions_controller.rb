class SessionsController < ApplicationController
  def create
  	session[:omniauth_auth] = auth_hash
    redirect_to root_url
  end

  protected

  def auth_hash
    request.env['omniauth.auth']
  end
end