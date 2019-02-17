# -*- coding: utf-8 -*-
# Copyright (c) 2017 Dunin Ilya.
"""
Flask RESTful API service. The main service purpose is to sign certificate request with rootCA certificate.
"""

# TODO: consider change configuration according to http://flask.pocoo.org/docs/0.12/config/#development-production
# TODO: using django style
# TODO: fix app.logger.info for production (currently in production env, filtered all messages except WARNING and ERROR
# TODO: but actually settings for logger: file_hnd.setLevel(logging.INFO). w/a use separate logger, but it looks like
# TODO: hack

from logging.handlers import RotatingFileHandler
from os import getenv, path, mkdir
import logging

from flask import Flask, jsonify, make_response, request, abort
from auth import authorise
from certificate_authority import CertificateAuthority, CAError

REQUEST_FIELDS = ['Expiry-days', 'Username', 'Password']

if not getenv('FLASK_CONFIGURATION'):
    raise RuntimeError('Flask env variable \'FLASK_CONFIGURATION\' nof found!')


def set_logger():
    """
    Configure service file logger
    """
    log_filename = 'logs/ca_service.log'
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(module)s:%(funcName)s:%(lineno)s] %(message)s',
                                  datefmt='%Y-%m-%d %H:%M:%S')
    file_hnd = RotatingFileHandler(path.join(app.root_path, log_filename), backupCount=5, maxBytes=(10 * 1024 * 1024))
    file_hnd.setLevel(logging.INFO)
    file_hnd.setFormatter(formatter)
    app.logger.addHandler(file_hnd)


app = Flask(__name__)  # pylint: disable=invalid-name
app.config.from_json(getenv('FLASK_CONFIGURATION'))
set_logger()


@app.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({'ERROR': error.description}), 400)


@app.errorhandler(401)
def unauthorized(error):
    return make_response(jsonify({'ERROR': error.description}), 401)


@app.errorhandler(422)
def not_found(error):
    return make_response(jsonify({'ERROR': error.description}), 422)


@app.route('/ca/api/v1.0/csr', methods=['POST'])
def process_csr():
    """
    Process Certificate Signing Request based on request data.
    :return: generated certificate {'certificate': [certificate]}
    """
    def valid_request():
        """
        Check that csr post request is valid: all fields from REQUEST_FIELDS exists
        :return: True if request.json not None and all fields found, else False
        """
        return all(param in request.headers for param in REQUEST_FIELDS)

    if not valid_request():
        msg = 'Not all mandatory header params ({}) provided! Check request!'.format(', '.join(REQUEST_FIELDS))
        app.logger.error(msg)
        abort(422, msg)

    ua = request.headers['User-Agent']
    host = request.headers['Host']

    username = request.headers['Username']
    password = request.headers['Password']
    expiry_days = request.headers['Expiry-days']
    csr = request.data

    if not authorise(username, password):  # TODO: not implemented yet
        abort(401, 'Cannot authorise user: "{}". Host/User-Agent: {} / {}'.format(username, host, ua))

    days = min(int(expiry_days), app.config.get('MAX_EXPIRY'))
    try:
        ca = CertificateAuthority(csr, app.config.get('INDEX_DB'))
        cert, cert_cn, cert_expiry, cert_sn = ca.sign_request(
            app.config.get('ROOT_CERT'),
            app.config.get('PRIVATE_KEY'),
            days
        )
        app.logger.warning('Certificate generated: "{}"\t"{}"\t"{}"\t"{}"'.format(username,
                                                                                  cert_cn,
                                                                                  cert_expiry,
                                                                                  cert_sn))
        save_certificate(cert.decode('utf-8'), cert_sn)
        return make_response(cert, 200)
    except CAError as exc:
        app.logger.error('Certificate for user "{}" from Host: "{}" not generated!\n{}'.format(username, host, exc))
        abort(422, str(exc))


def save_certificate(cert, serial_number):
    """ Save signed certificate to file
    :param cert: certificate
    :param serial_number: certificate serial number
    """
    cert_fn = path.join(app.config.get('NEW_CERT_DIR'), '{}.pem'.format(serial_number))
    try:
        with open(cert_fn, 'w') as fd:
            fd.write(cert)
    except IOError:
        app.logger.error("Cannot save certificate: {}".format(cert_fn))


if __name__ == '__main__':
    context = None  # pylint: disable=invalid-name
    if not app.config.get('DEBUG'):
        context = (app.config.get('ROOT_CERT'), app.config.get('PRIVATE_KEY'))  # pylint: disable=invalid-name

    if not app.config.get('INDEX_DB'):
        app.logger.error('Cannot start service! INDEX_DB env nof found!')
        exit(1)

    if not path.exists(app.config.get('INDEX_DB')):
        app.logger.error('Cannot start service! File {} not found!'.format(app.config.get('INDEX_DB')))
        exit(1)

    if not app.config.get('NEW_CERT_DIR'):
        app.logger.error('Cannot start service! NEW_CERT_DIR nof found!')
        exit(1)

    if not path.isdir(app.config.get('NEW_CERT_DIR')):
        mkdir(app.config.get('NEW_CERT_DIR'))

    try:
        app.run(
            host=app.config.get('HOST'),
            port=app.config.get('PORT'),
            debug=app.config.get('DEBUG'),
            ssl_context=context
        )
    except FileNotFoundError as exc:
        app.logger.error('Cannot load certificate: {}'
                         '\nCheck settings/production.json "ROOT_CERT" and "PRIVATE_KEY" values'.format(exc))
        exit(1)
