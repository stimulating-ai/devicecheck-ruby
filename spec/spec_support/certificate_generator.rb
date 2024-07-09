# frozen_string_literal: true

module SpecSupport
  module CertificateGenerator
    def generate_key
      OpenSSL::PKey::EC.generate('prime256v1')
    end

    def generate_root_cert(root_dn, root_key)
      cert = generate_cert(root_dn, root_key, 0, issuer: root_dn)
      mark_as_ca(cert)
      cert.sign(root_key, 'sha256')
      cert
    end

    def mark_as_ca(cert)
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = cert
      ef.issuer_certificate = cert
      cert.add_extension(ef.create_extension('basicConstraints', 'CA:TRUE', true))
    end

    def generate_cert(subject, key, serial, issuer: nil, not_after: nil)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = serial
      cert.subject = subject
      cert.issuer = issuer
      cert.public_key = key
      now = Time.now
      cert.not_before = now - 3600
      cert.not_after = not_after || (now + 3600)
      cert
    end
  end
end
