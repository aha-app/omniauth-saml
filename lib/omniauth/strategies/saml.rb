require 'omniauth'
require 'ruby-saml'

module OmniAuth
  module Strategies
    class SAML
      include OmniAuth::Strategy

      option :name_identifier_format, nil
      option :idp_sso_target_url_runtime_params, {}

      def request_phase
        options[:assertion_consumer_service_url] ||= callback_url
        runtime_request_parameters = options.delete(:idp_sso_target_url_runtime_params)

        additional_params = {}
        runtime_request_parameters.each_pair do |request_param_key, mapped_param_key|
          additional_params[mapped_param_key] = request.params[request_param_key.to_s] if request.params.has_key?(request_param_key.to_s)
        end if runtime_request_parameters

        authn_request = OneLogin::RubySaml::Authrequest.new
        settings = OneLogin::RubySaml::Settings.new(options)

        redirect(authn_request.create(settings, additional_params))
      end

      def callback_phase
        unless request.params['SAMLResponse']
          raise OmniAuth::Strategies::SAML::ValidationError.new("SAML response missing")
        end
        
        Rails.logger.debug("SAML response: #{request.params['SAMLResponse']}") if defined? Rails
        Rails.logger.debug("Decoded SAML response: #{Base64.decode64(request.params['SAMLResponse'])}") if defined? Rails
        
        # Call a fingerprint validation method if there's one
        if options.idp_cert_fingerprint_validator
          fingerprint_exists = options.idp_cert_fingerprint_validator[response_fingerprint]
          unless fingerprint_exists
            raise OmniAuth::Strategies::SAML::ValidationError.new("SAML response certificate does not match fingerprint")
          end
          # id_cert_fingerprint becomes the given fingerprint if it exists
          options.idp_cert_fingerprint = fingerprint_exists
        end

        response = OneLogin::RubySaml::Response.new(request.params['SAMLResponse'], options)
        response.settings = OneLogin::RubySaml::Settings.new(options)

        @name_id = response.name_id
        @attributes = response.attributes

        if @name_id.nil? || @name_id.empty?
          raise OmniAuth::Strategies::SAML::ValidationError.new("SAML response missing 'NameID'. This usually means the Identity Provider is not configured or the user does not have permission for the application.")
        end

        unless response.is_valid?
          raise OmniAuth::Strategies::SAML::ValidationError.new(response.errors.join(', '))
        end
        
        super
      rescue OmniAuth::Strategies::SAML::ValidationError
        fail!(:invalid_ticket, $!)
      rescue OneLogin::RubySaml::ValidationError
        fail!(:invalid_ticket, $!)
      end

      # Obtain an idp certificate fingerprint from the response.
      def response_fingerprint
        response = request.params['SAMLResponse']
        response = (response =~ /^</) ? response : Base64.decode64(response)
        document = XMLSecurity::SignedDocument::new(response)
        cert_element = REXML::XPath.first(document, "//ds:X509Certificate", { "ds"=> 'http://www.w3.org/2000/09/xmldsig#' })
        if cert_element.nil?
          raise OmniAuth::Strategies::SAML::ValidationError.new("SAML response missing X.509 certificate.")
        end
        base64_cert = cert_element.text
        cert_text = Base64.decode64(base64_cert)
        cert = OpenSSL::X509::Certificate.new(cert_text)
        Digest::SHA1.hexdigest(cert.to_der).upcase.scan(/../).join(':')
      end

      def other_phase
        if on_path?("#{request_path}/metadata")
          # omniauth does not set the strategy on the other_phase
          @env['omniauth.strategy'] ||= self
          setup_phase

          response = OneLogin::RubySaml::Metadata.new
          settings = OneLogin::RubySaml::Settings.new(options)
          Rack::Response.new(response.generate(settings), 200, { "Content-Type" => "application/xml" }).finish
        else
          call_app!
        end
      end

      uid { @name_id }

      info do
        {
          :name  => @attributes['FullName'] || @attributes[:name] || @attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'],
          :email => @attributes['EmailAddress'] || @attributes[:email] || @attributes[:mail] || @attributes[:emailAddress] || @attributes['Email'] ||@attributes['User.email'] || @attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'] || @attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'],
          :first_name => @attributes['FirstName'] || @attributes[:first_name] || @attributes[:firstname] || @attributes[:firstName] || @attributes['User.FirstName'] || @attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'],
          :last_name => @attributes['LastName'] || @attributes[:last_name] || @attributes[:lastname] || @attributes[:lastName] || @attributes['User.LastName'] || @attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname']
        }
      end

      extra { { :raw_info => @attributes } }
    end
  end
end

OmniAuth.config.add_camelization 'saml', 'SAML'
