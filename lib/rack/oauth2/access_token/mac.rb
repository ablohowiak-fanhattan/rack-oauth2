module Rack
  module OAuth2
    class AccessToken
      class MAC < AccessToken
        attr_required :mac_key, :mac_algorithm
        attr_optional :issued_at, :ext
        attr_reader :nonce, :body_hash, :signature

        def initialize(attributes = {})
          super(attributes)
          @issued_at ||= Time.now.utc
        end

        def token_response
          super.merge(
            :mac_key => mac_key,
            :mac_algorithm => mac_algorithm
          )
        end

        def verify!(request)
          puts "In oauth2 gem verifying request"
          if request.body_hash.present?
            begin
              puts "body_hash is present!"
              BodyHash.new(
                :raw_body  => request.body.read,
                :algorithm => self.mac_algorithm
              ).verify!(request.body_hash)
              puts "body_hash was verified"
            ensure
              puts "body_hash verification over"
            end
          end
          begin
            params = {
              :secret      => self.mac_key,
              :algorithm   => self.mac_algorithm,
              :nonce       => request.nonce,
              :method      => request.request_method,
              :request_uri => request.fullpath,
              :host        => request.host,
              :port        => request.port,
              :body_hash   => request.body_hash,
              :ext         => request.ext
            }

            puts "begin signature verify with params: #{params}"
            Signature.new(params).verify!(request.signature)
            puts "Signature verify is complete."
          ensure
            puts "Signature verify is over."
          end
        rescue Verifier::VerificationFailed => e
          puts "verification failed in mac.rb #{e.message} #{e.backtrace} #{caller}"
          request.invalid_token! e.message
        end

        def authenticate(request)
          @nonce = generate_nonce
          if request.contenttype == 'application/x-www-form-urlencoded'
            @body_hash = BodyHash.new(
              :raw_body => request.body,
              :algorithm => self.mac_algorithm
            ).calculate
          end
          @signature = Signature.new(
            :secret      => self.mac_key,
            :algorithm   => self.mac_algorithm,
            :nonce       => self.nonce,
            :method      => request.header.request_method,
            :request_uri => request.header.create_query_uri,
            :host        => request.header.request_uri.host,
            :port        => request.header.request_uri.port,
            :body_hash   => self.body_hash,
            :ext         => self.ext
          ).calculate
          request.header['Authorization'] = authorization_header
        end

        private

        def authorization_header
          header = "MAC"
          header << " id=\"#{access_token}\","
          header << " nonce=\"#{nonce}\","
          header << " bodyhash=\"#{body_hash}\"," if body_hash.present?
          header << " ext=\"#{ext}\"," if ext.present?
          header << " mac=\"#{signature}\""
        end

        def generate_nonce
          [
            (Time.now.utc - @issued_at).to_i,
            SecureRandom.hex
          ].join(':')
        end
      end
    end
  end
end

require 'rack/oauth2/access_token/mac/verifier'
require 'rack/oauth2/access_token/mac/body_hash'
require 'rack/oauth2/access_token/mac/signature'
