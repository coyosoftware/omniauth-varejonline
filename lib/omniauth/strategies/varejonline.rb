require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class Varejonline < OmniAuth::Strategies::OAuth2

      # Possible scopes: userinfo.email,userinfo.profile,plus.me
      DEFAULT_SCOPE = "all"

      option :name, 'varejonline'
      option :authorize_options, [:client_id, :redirect_uri, :client_secret]
      option :provider_ignores_state, true

      option :client_options, {
        :site          => 'https://erp.varejonline.com.br',
        :authorize_url => '/apps/oauth/authorization?response_type=code',
        :token_url     => '/apps/oauth/token'
      }

      def build_access_token
        verifier = request.params["code"]
        
        client.auth_code.get_token(verifier, {:redirect_uri => callback_url.gsub(/\?(.*)/, "")}.merge(token_params.to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))
      end

      info do
        prune!({
          :cnpj_empresa => raw_info['cnpj_empresa'],
          :id_terceiro => raw_info['id_terceiro'],
          :nome_terceiro  => raw_info['nome_terceiro']
        })
      end

      def raw_info
        @raw_info ||= build_access_token
      end

      private

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end
    end
  end
end