## OpenSSL Common Commands

### Generate self-signed Certificate and Key

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mykey.key -out mycert.crt
```

---

### Generate a New Key

```bash
openssl genrsa -out server.key 2048
```

### Generate a New Key (AES 256 CBC)

```bash
openssl genrsa -aes-256-cbc -out rootca.key 2048
```

### Generate a New Key (ECC-256)

```bash
openssl ecparam -genkey -name secp256k1 -out rootca.key
```

### Generate a New Key (AES 256 CBC) and a random Passphrase

```bash
export PASSPHRASE=$(tr -dc 'a-zA-Z0-9!@#$%^&*:./?=+_[]{}()<>' < /dev/urandom | head -c 50)
openssl genrsa -aes-256-cbc -out rootca.key -passout env:PASSPHRASE 2048
```

---

### Generate Certificate Signing Request in PKCS#10 format

```bash
openssl req -new -sha256 -key server.key -out server.req
```

### Generate Certificate Signing Request

```bash
subj="
C=$COUNTRY
ST=$STATE
L=$CITY
O=$ORGANIZATION
OU=$ORGANIZATION_UNIT
CN=$COMMON_NAME
emailAddress=$ADMIN_EMAIL
"

openssl req -new -sha256 -batch -subj "$(echo -n "$subj" | tr "\n" "/")" -key rootca.key -out rootca.csr -passin env:PASSPHRASE
```

---

### Generate CRT from CSR

```bash
openssl x509 -req -sha256 -days 365 -in rootca.csr -signkey rootca.key -out rootca.crt
```

---

### Sign CSR with ROOT CA

```bash
openssl x509 -req -sha256 -days 365 -in mycert.csr -CA rootca.crt -CAkey rootca.key -CAcreateserial -out mycert.crt
```

---

### Convert CER to ascii(crt)

```bash
openssl x509 -inform DER -in subdomain.twelvesec.int.cer -out subdomain.twelvesec.int.crt
```

---

### Generate a New CSR and Key

```bash
openssl req -nodes -new -newkey rsa:<number of bits> -out <filename-csr> -keyout <filename-key>
```

e.g.

```bash
openssl req -nodes -new -newkey rsa:2048 -out subdomain.example.com.csr -keyout subdomain.example.com.key
```

### Generate a New CSR from Existing Key

```bash
openssl req -nodes -new -key <filename-key> -out <filename-csr>
```

e.g.

```bash
openssl req -nodes -new -key subdomain.example.com.old.key -out subdomain.example.com.new.csr
```

### Generate a New CSR from Existing CRT and Key

```bash
openssl x509 -x509toreq -in <filename-crt> -key <filename-key> -out <filename-csr>
```

e.g.

```bash
openssl x509 -x509toreq -in subdomain.example.com.old.crt -key subdomain.example.com.key -out subdomain.example.com.csr
```

---

### Remove RSA private key PEM password

```bash
openssl rsa -in ~/.ssh/id_rsa -out ~/.ssh/id_rsa_2
mv ~/.ssh/id_rsa_2 ~/.ssh/id_rsa
chmod 0400 ~/.ssh/id_rsa
```

---

### Create a CSR with SANs

```bash
openssl req -new -sha256 -key subdomain.example.com.key -out subdomain.example.com.req -config myssl.cnf
```

or

```bash
openssl req -new -sha256 -nodes -newkey rsa:<number of bits> -out <filename-csr> -keyout <filename-key> -config myssl.cnf
```

e.g.

```bash
openssl req -new -sha256 -nodes -newkey rsa:4096 -out subdomain.example.com.csr -keyout subdomain.example.com.key -config myssl.conf
```

#### myssl.cnf Contents

```
[req]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt = no

[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= GR
countryName_min			= 2
countryName_max			= 2
stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= Attiki
localityName			= Locality Name (eg, city)
localityName_default	= Athens
0.organizationName		= Organization Name (eg, company)
0.organizationName_default	= MyCompany
organizationalUnitName		= Organizational Unit Name (eg, section)
organizationalUnitName_default	= Operations
commonName			= Common Name (eg, YOUR name)
commonName_default  = subdomain.example.com
commonName_max		= 64
emailAddress			= Email Address
emailAddress_default	= info@example.com
emailAddress_max		= 40

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1   = subdomain.example.com
```

---

### Read a CSR

```bash
openssl req -text -noout -in <filename-csr>
```

### Read a CRT

```bash
openssl x509 -text -noout -in <filename-crt>
```

### Verify a CRT matches a Private Key

```bash
openssl x509 -noout -modulus -in <filename-crt>
```

---

### Client-side SSL

```bash
openssl genrsa -out <user-name>.key 2048
openssl req -new -sha256 -key <user-name>.key -out <user-name>.req
openssl x509 -req -in <user-name>.req -CA ca.cer -CAkey ca.key -set_serial 110 -extensions client -days 365 -outform PEM -out <user-name>.cer
openssl pkcs12 -export -inkey <user-name>.key -in <user-name>.cer -out <user-name>.p12
rm <user-name>.key <user-name>.cer <user-name>.req
cp <user-name>.p12 /home/<user-name>/myfolder/
chown <user-name>: /home/<user-name>/myfolder/<user-name>.p12
```

---

### Sign files

```bash
openssl dgst -sha256 -sign mycert.key -out sign.sha256 filename.txt
openssl base64 -in sign.sha256 -out sign.base64
```

### Verify files

```bash
openssl x509 -in cert.crt -pubkey -noout > cert.pub
openssl dgst -sha256 -verify cert.pub -signature sign.sha256 filename.txt
```

---

### Encrypt files

```bash
openssl rsa -in mycert.key -pubout -outform PEM -out publickey.pem
openssl rsautl -encrypt -inkey publickey.pem -pubin -in filename.txt -out filename_encrypted.enc
```

### Decrypt files

```bash
openssl rsautl -decrypt -inkey mycert.key -in filename_encrypted.enc -out filename.txt
```

---
