# CA Service
Service allows to serve CA requests and sign requests with company root certificate.
This service do almost the same as openssl tool.

## Prerequisites
* Python 3.6

## Installation
* Create virtualenv for python 3.6
* Install all required packages: `pip install -r ca_srvc_api/requirements.txt`

## Configuration
We need to create directories structure and files

### Directories and files uses by service
```
> mkdir -p ~/CA/{newcert,private}
> touch ~/CA/index.txt
```
Or it is possible simply update `settings/production.json` with existing values

### Generate root key and root certificate
* root key: `openssl genrsa -out ~/CA/private/rootCA.key 2048`
* root certificate: `openssl req -x509 -new -key ~/CA/private/rootCA.key -days 365 -out ~/CA/rootCA.crt`

### Update config variables
Update variables for both configuration files: `settings/production.json` and `settings/development.json`
* "ROOT_CERT": "/home/[username]/CA/rootCA.crt" 
* "PRIVATE_KEY": "/home/[username]/CA/private/rootCA.key"
* "INDEX_DB": "/home/[username]/CA/index.txt"
* "NEW_CERT_DIR": "/home/[username]/CA/newcert"

## Start service
`FLASK_CONFIGURATION=settings/production.json python3 ca_srvc_api.py`

## TODO
Add tests

# CA client
1. *ca_client.sh* script to create public/private keys. And sent CSR request

