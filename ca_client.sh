#!/usr/bin/env bash

CA_SERVICE='http://127.0.0.1:5000'  # change here for your service address
API_CSR='ca/api/v1.0/csr'
DOMAIN='domain.com'  # change here for company domain

EXPIRY=2  # default value

# Check exit code and exit if not zero.
function exit_code()
{
    if [ $1 -ne 0 ]; then
        echo "$2" >&2
        exit 1
    fi
}

# Check that username is valid
function check_username()
{
    echo "$1" | grep '@' > /dev/null
    if [ $? -eq 0 ]; then
        echo "ERROR: Incorrect username: $1 (username shouldn't contain @ character)!" >&2
        exit 1
    fi
}

function usage()
{
    read -d '' text << EOF
Sample usage: ca_client.sh [options]
    Where options:
    -c: Common Name (also CN)
    -u: username
    -p: one time password
    -e: certificate expiry days
EOF
    echo "$text"
}

# Generate private key file
function generate_key()
{
    openssl genrsa -out "$1.key" 2048
    exit_code $? "Cannot generate private key!"
}

# Generate CSR file using private key
function generate_csr()
{
    # csr 2 text command
    # openssl req -noout -text -in [csr_file]
    openssl req -new -key "$1.key" -out "$1.csr" -subj "/C=CZ/CN=$1/emailAddress=$2@$DOMAIN"
    exit_code $? "Cannot generate csr!"
}

# Send CSR to service
function send_csr()
{
    csr_file="$1.csr"
    cert="$1.pem"

    wget --tries=3 \
	     --post-file="$csr_file" \
         --header="Content-Type: application/binary" \
         --header="Username:$2" \
         --header="Password:$3" \
         --header="Expiry-days:$4" \
         -O "$cert" \
         --no-check-certificate \
         "$CA_SERVICE/$API_CSR"

    # openssl x509 -in [cert] -text -noout  / https://www.sslchecker.com/certdecoder
    exit_code $? "Cannot generate certificate!"
    echo "Certificate saved to file: $(realpath "$cert")"
}

# Check that command line not empty
if [[ -z $* ]]
then
    (>&2 echo "ERROR: No options found!")
    usage
    exit 1
fi

while getopts "c:u:p:e:" opt
    do
        case $opt in
        c) CN=$OPTARG ;;
        u) USERNAME=$OPTARG ;;
        p) OTP=$OPTARG ;;
        e) EXPIRY=$OPTARG ;;
        *) (>&2 echo "ERROR: Invalid options found!")
        exit 1 ;;
    esac
done

check_username $USERNAME

if [[ ! -z "$CA_SERVICE" ]]
then
	CA_SERVICE=$CA_SERVICE
fi

echo "Trying to generate certificate for user: \"$USERNAME\" with CN=$CN for $EXPIRY days!"
generate_key $CN
generate_csr $CN $USERNAME
echo "Sending request to: ${CA_SERVICE}${API_CSR}"
send_csr $CN $USERNAME $OTP $EXPIRY
echo "Certificate generated!"

exit 0
