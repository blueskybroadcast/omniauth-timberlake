require 'omniauth-oauth2'
require 'rest_client'
require 'multi_xml'

module OmniAuth
  module Strategies
    class Timberlake < OmniAuth::Strategies::OAuth2
      option :name, 'timberlake'

      option :client_options, {
        authorize_url: 'http://staging.membershipsoftware.org/login.asp',
        api_base_url: 'https://secure005.membershipsoftware.org/stagingsecure',
        user_info_url: '/api/getmemberinfo',
        validate_url: '/api/ValidateAuthenticationToken',
        security_key: 'MUST BE SET'
      }

      uid { raw_info[:id] }

      info do
        {
          first_name: raw_info[:first_name],
          last_name: raw_info[:last_name],
          email: raw_info[:email],
          member_id: uid,
          member_type: raw_info[:member_type],
          is_active: raw_info[:is_active],
          is_member: raw_info[:is_member]
        }
      end

      extra do
        { :raw_info => raw_info }
      end

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//,"")
        redirect authorize_url + "?redirectURL=" + callback_url + "?slug=#{slug}"
      end

      def callback_phase
        self.access_token = {
          :token => request.params['AuthenticationToken'],
          :token_expires => 60
        }
        self.env['omniauth.auth'] = auth_hash
        call_app!
      end

      def creds
        self.access_token
      end

      def auth_hash
        hash = AuthHash.new(:provider => name, :uid => uid)
        hash.info = info
        hash.credentials = creds
        hash.extra = extra
        hash
      end

      def raw_info
        @raw_info ||= get_user_info
      end

      def validate_auth_token
        response = RestClient.get(validate_auth_url,
          { :params =>
            {
              "token" => access_token[:token],
              "securityKey" => security_key
            }
          }
        )

        parsed_response = MultiXml.parse(response)

        if response.code == 200
          parsed_response['ValidateAuthenticationToken']['ValidateAuthenticationTokenResult']
        else
          nil
        end
      end

      def get_user_info
        response = RestClient.get(user_info_url,
          { :params =>
            {
              "securityKey" => security_key,
              "memberKey" => validate_auth_token
            }
          }
        )

        parsed_response = MultiXml.parse(response)

        if response.code == 200
          info = {
            id: parsed_response['GetMemberInfo']['MemberID'],
            first_name: parsed_response['GetMemberInfo']['FirstName'],
            last_name: parsed_response['GetMemberInfo']['LastName'],
            email: parsed_response['GetMemberInfo']['EmailAddress'],
            member_type: parsed_response['GetMemberInfo']['MemberType'],
            is_active: parsed_response['GetMemberInfo']['IsActive'],
            is_member: parsed_response['GetMemberInfo']['IsMember']
          }
        else
          nil
        end
      end

      private

      def authorize_url
        options.client_options.authorize_url
      end

      def format_end_date(date)
        split_date = date.split('/')
        Date.parse "#{split_date[2]}-#{split_date[0]}-#{split_date[1]}"
      end

      def security_key
        options.client_options.security_key
      end

      def user_info_url
        "#{options.client_options.api_base_url}#{options.client_options.user_info_url}"
      end

      def validate_auth_url
        "#{options.client_options.api_base_url}#{options.client_options.validate_url}"
      end
    end
  end
end
