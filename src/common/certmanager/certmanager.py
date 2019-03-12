# coding: utf-8

import os
import logging
from OpenSSL import crypto
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from ..utils import load_file_raw

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('CM')
logger.setLevel(logging.DEBUG)

class CertManager:

    def __init__(self, cert = None, priv_key = None, pub_key = None):

        if cert:
            if (cert.startswith( b'-----BEGIN CERTIFICATE-----' )):
                self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
                raw = crypto.dump_publickey(crypto.FILETYPE_PEM, self.cert.get_pubkey())
            else:
                self.cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
                raw = crypto.dump_publickey(crypto.FILETYPE_ASN1, self.cert.get_pubkey())

            rsakey = RSA.importKey(raw)
            self.pub_key = PKCS1_v1_5.new(rsakey)
            self.pub_key_enc = PKCS1_OAEP.new(rsakey, SHA256)

        if priv_key:
            rsakey = RSA.importKey(priv_key)
            self.priv_key = PKCS1_v1_5.new(rsakey)
            self.priv_key_enc = PKCS1_OAEP.new(rsakey, SHA256)

        if pub_key:
            self.pub_key_enc = PKCS1_OAEP.new(RSA.importKey(pub_key), SHA256)

    def sign(self, data, priv_key = None):
        """
            Signing data with Signature Private Key
        """

        private_key = priv_key
        if not priv_key:
            if not self.priv_key:
                logger.error("No private key given")
                return
            private_key = self.priv_key

        h = SHA256.new(data)
        return private_key.sign( h )

    def verify_signature(self, signature, data, pub_key = None):
        """
            Validate signature for certain data
        """

        public_key = pub_key
        if not pub_key:
            if not self.pub_key:
                logger.error("No public key given")
                return False
            public_key = self.pub_key

        digest = SHA256.new()
        digest.update(data)

        return public_key.verify(digest, signature)

    def encrypt(self, plaintext, pub_key = None):
        """
            Encrypt text with given or set pub_key
        """

        if pub_key != None:
            public_key = PKCS1_OAEP.new(RSA.importKey(pub_key), SHA256)
        elif self.pub_key != None:
            public_key = self.pub_key_enc
        else:
            logger.error("No public key given")
            return False

        return public_key.encrypt( plaintext )

    def decrypt(self, ciphertext, priv_key = None):
        """
            Decrypt cipher_text with given or set priv_key
        """

        if priv_key != None:
            rsakey = RSA.importKey(priv_key)
            private_key = PKCS1_v1_5.new(rsakey)
            private_key_enc = PKCS1_OAEP.new(rsakey, SHA256)
        elif self.priv_key != None:
            private_key = self.priv_key
            private_key_enc = self.priv_key_enc
        else:
            logger.error("No private key given")
            return False

        return private_key_enc.decrypt( ciphertext )

    def verify_certificate(self, cert = None):
        """
           Validated certificate via chain of trust
        """

        certificate = cert
        if not cert:
            if not self.cert:
                logger.error("No certificate given")
                return False
            certificate = self.cert

        store = crypto.X509Store()

        for filename in os.listdir('src/common/certmanager/certs'):
            f = open('src/common/certmanager/certs/' + filename, 'rb')
            cert_text = f.read()
            try:
                # PEM FORMAT
                if (cert_text.startswith( b'-----BEGIN CERTIFICATE-----' )):
                    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_text)
                # ASN1 FORMAT
                else:
                    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_text)

                store.add_cert(cert)
            except Exception as e:
                logger.error("Unable to read certificate: %s", filename)
                continue

        store_ctx = crypto.X509StoreContext(store, certificate)

        result = store_ctx.verify_certificate()

        return True if not result else False

    def get_identity(self, cert = None):
        certificate = cert
        if not cert:
            if not self.cert:
                logger.error("No certificate given")
                return False
            certificate = self.cert

        subject = certificate.get_subject()
        return (subject.CN, subject.serialNumber[2:-1])

    @staticmethod
    def get_cert_by_name(cert_name):
        '''
            Returns raw certificate from certs directory
        '''
        content = load_file_raw('src/common/certmanager/certs/' + cert_name)
        if content is None:
            logger.error("Unable to read certificate: %s", cert_name)
        return content
