# -*- coding: utf-8 -*-
# Copyright (c) 2018 Dunin Ilya.
"""
Certificate Authority module.
"""

from OpenSSL import crypto
from uuid import uuid1

from index_db import IndexDB, DatabaseError

DOMAIN = '@domain.com'
SHA256 = "sha256"


class CAError(ValueError):
    """ CAError exception class. Raised in case of incorrect certificate request """
    pass


def _get_cert_object(cert_file):
    with open(cert_file) as cf:
        return crypto.load_certificate(crypto.FILETYPE_PEM, cf.read())


def _get_key_object(key_file):
    with open(key_file) as kf:
        return crypto.load_privatekey(crypto.FILETYPE_PEM, kf.read())


class CertificateAuthority:
    """ CertificateAuthority class """
    def __init__(self, csr, index_db_path):
        """
        Create instance of CertificateAuthority and validate CSR
        :param csr: certificate request
        :raise CAError: raised in CSR invalid
        """
        self._csr = None

        try:
            self.index_db = IndexDB(index_db_path)
        except DatabaseError as exc:
            raise CAError(exc)

        try:
            self._csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
            email = self._csr.get_subject().emailAddress
            if not email or not email.endswith(DOMAIN):  # TODO: improve validation
                raise CAError('Incorrect certificate! Email not found or incorrect!\n'
                              'Expected [username]{}; Got: {}\n'
                              'Generate certificate using ca_client.py!'.format(DOMAIN, email))
        except crypto.Error as exc:
            raise CAError(exc)

    def sign_request(self, issuer_cert, issuer_key, expiry, digest=SHA256):
        """
        Generate a certificate given a certificate request.
        :param issuer_cert: The certificate of the issuer
        :param issuer_key: The private key of the issuer
        :param expiry: Expiry days
        :param digest: Digest method to use for signing, default is sha256
        :return: The signed certificate in an X509 object
        :raise CAError: raised if certificate/private key invalid
        """
        try:
            cert = crypto.X509()
            cert.set_serial_number(uuid1().int)
            cert.gmtime_adj_notBefore(0)  # Not adjust before value. Will take current timestamp (datetime.now())
            cert.gmtime_adj_notAfter(expiry * 24 * 60 * 60)  # Expiry values should be in seconds
            cert.set_issuer(_get_cert_object(issuer_cert).get_subject())
            cert.set_subject(self._csr.get_subject())
            cert.set_pubkey(self._csr.get_pubkey())
            cert.sign(_get_key_object(issuer_key), digest)

            self.index_db.update(cert.get_notAfter().decode('utf-8'),
                                 cert.get_serial_number(),
                                 cert.get_subject().CN
                                 )

            return (crypto.dump_certificate(crypto.FILETYPE_PEM, cert),
                    cert.get_subject().CN,
                    cert.get_notAfter().decode('utf-8'),
                    cert.get_serial_number())
        except (crypto.Error, DatabaseError) as exc:
            raise CAError(exc)
