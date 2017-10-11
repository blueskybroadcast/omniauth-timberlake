require 'omniauth-oauth2'
require 'rest_client'
require 'multi_xml'

module OmniAuth
  module Strategies
    class Timberlake < OmniAuth::Strategies::OAuth2
      option :name, 'timberlake'

      option :app_options, { app_event_id: nil }

      option :client_options, {
        authorize_url: 'https://staging.membershipsoftware.org/login.asp',
        api_base_url: 'https://secure005.membershipsoftware.org/stagingsecure',
        user_info_url: 'api/GetBasicMemberInfo/',
        validate_url: 'api/ValidateAuthenticationToken/',
        security_key: 'MUST BE SET'
      }

      uid { raw_info[:id] }

      info do
        {
          id: raw_info[:id],
          first_name: raw_info[:first_name],
          last_name: raw_info[:last_name],
          email: raw_info[:email],
          member_type: raw_info[:member_type],
          expiration_date: raw_info[:expiration_date]
        }
      end

      extra do
        { raw_info: raw_info }
      end

      def request_phase
        redirect authorize_url + '?redirectURL=' + callback_url + "?slug=#{account_slug}"
      end

      def callback_phase
        slug = request.params['slug']
        account = Account.find_by(slug: slug)
        @app_event = account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')

        self.access_token = {
          token: request.params['AuthenticationToken'],
          token_expires: 60
        }
        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.app_event_id'] = @app_event.id
        call_app!
      end

      def creds
        self.access_token
      end

      def auth_hash
        hash = AuthHash.new(provider: name, uid: uid)
        hash.info = info
        hash.credentials = creds
        hash.extra = extra
        hash
      end

      def raw_info
        @raw_info ||= get_user_info
      end

      def validate_auth_token
        Rails.logger.error("\n==========================================\n\n #{validate_auth_url} \n\n==========================================\n")
        request_log_text = "#{provider_name} Validate Auth Token Request:\nGET #{filtered_url(validate_auth_url)}"
        @app_event.logs.create(level: 'info', text: request_log_text)

        begin
          response = RestClient.get(validate_auth_url)
        rescue RestClient::ExceptionWithResponse => e
          create_response_error_log(e.response, e.message)
          return
        end

        parsed_response = MultiXml.parse(response)
        if response.code == 200
          response_log_text = "#{provider_name} Validate Auth Token Response (code: #{response.code}): \n#{response}"
          @app_event.logs.create(level: 'info', text: response_log_text)

          @contact_id = parsed_response['ValidateAuthenticationToken']['ValidateAuthenticationTokenResult']
          parsed_response['ValidateAuthenticationToken']['ValidateAuthenticationTokenResult']
        else
          create_response_error_log(response)
          nil
        end
      end

      def get_user_info
        Rails.logger.error("\n==========================================\n\n #{user_info_url} \n\n==========================================\n")
        request_log_text = "#{provider_name} Get Basic Member Info Request:\nGET #{filtered_url(user_info_url)}"
        @app_event.logs.create(level: 'info', text: request_log_text)

        begin
          response = RestClient.get(user_info_url)
        rescue RestClient::ExceptionWithResponse => e
          create_response_error_log(e.response, e.message)
          return
        end

        parsed_response = MultiXml.parse(response)
        if response.code == 200
          response_log_text = "#{provider_name} Validate Auth Token Response (code: #{response.code}): \n#{response}"
          @app_event.logs.create(level: 'info', text: response_log_text)

          info = {
            id: @contact_id,
            first_name: parsed_response['GetBasicMemberInfo']['FirstName'],
            last_name: parsed_response['GetBasicMemberInfo']['LastName'],
            email: parsed_response['GetBasicMemberInfo']['EmailAddress'],
            member_type: parsed_response['GetBasicMemberInfo']['MemberType'],
            expiration_date: parsed_response['GetBasicMemberInfo']['ExpirationDate']
          }

          @app_event.update(raw_data: {
            user_info: {
              uid: info[:id],
              email: info[:email],
              first_name: info[:first_name],
              last_name: info[:last_name]
            }
          })

          info
        else
          create_response_error_log(response)
          nil
        end
      end

      private

      def create_response_error_log(response, error_message = '')
        error_log_text = "#{provider_name} Validate Auth Token Response Error #{error_message}(code: #{response&.code}):\n#{response}"
        @app_event.logs.create(level: 'error', text: error_log_text)
        @app_event.fail!
      end

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
        base_url = options.client_options.api_base_url
        base_url += '/' if options.client_options.api_base_url[-1] != '/'
        user_url = options.client_options.user_info_url
        user_url += '/' if options.client_options.user_info_url[-1] != '/'
        "#{base_url}#{user_url}?securitykey=#{security_key}&contactID=#{validate_auth_token}"
      end

      def validate_auth_url
        base_url = options.client_options.api_base_url
        base_url += '/' if options.client_options.api_base_url[-1] != '/'
        validate_url = options.client_options.validate_url
        validate_url += '/' if options.client_options.validate_url[-1] != '/'
        "#{base_url}#{validate_url}?securitykey=#{security_key}&token=#{access_token[:token]}"
      end

      def account_slug
        session['omniauth.params']['origin'].gsub(/\//, '')
      end

      def provider_name
        options.name
      end

      def filtered_url(url)
        url.gsub(/\?securitykey=.*&/, "?securitykey=#{Provider::SECURITY_MASK}")
           .gsub(/&token=.*/, "&token=#{Provider::SECURITY_MASK}")
      end
    end
  end
end
