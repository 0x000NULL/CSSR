### Revoke a certificate
```bash
./revoke-full CERTUSERNAME
```

* *this command should return an "error 23 at 0 depth lookup:certificate revoked"*
* *if the above doesn't work run:* 

```bash
source ./vars
```

### Debug
```bash
grep CERTUSERNAME easy-rsa/keys/*.pem
cp ??.pem CERTUSERNAME.crt
./revoke-full CERTUSERNAME
```
