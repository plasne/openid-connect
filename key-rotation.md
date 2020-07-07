<!-- markdownlint-disable MD029 -->
<!-- markdownlint-disable MD034 -->

# Key Rotation

You can only have 1 signing key, but you can have up to 4 validation certificates. This allows you to seamlessly rotate your signing key while still allowing older keys to be validated for some period of time.

## Criteria

Key rotation without downtime is only supported when the following is true:

* Any of PRIVATE_KEY, PRIVATE_KEY_PASSWORD, PUBLIC_CERT_0, PUBLIC_CERT_1, PUBLIC_CERT_2, and PUBLIC_CERT_3 that are defined are stored in Azure Key Vault.

* At least 2 of the variables PUBLIC_CERT_0, PUBLIC_CERT_1, PUBLIC_CERT_2, or PUBLIC_CERT_3 must be defined. The URL for Key Vault does not require a secret to be stored (i.e. it can return a 404), but the reference must be defined.

    For example, you might have "PUBLIC_CERT_0: https://pelasne-vault.vault.azure.net/secrets/PUBLIC-CERT-0" and "PUBLIC_CERT_1: https://pelasne-vault.vault.azure.net/secrets/PUBLIC-CERT-1" defined. However, you might not have an entry in Key Vault for PUBLIC-CERT-1. It will return a 404 on startup and ignore it. When you assign PUBLIC-CERT-1 in the Key Vault during key rotation, it will be picked up then.

## Steps

1. Create a new private key, certificate, and PFX file.

```bash
openssl req -x509 -newkey rsa:4096 -keyout privatekey.pem -out certificate.pem -days 365
openssl pkcs12 -export -inkey privatekey.pem -in certificate.pem -out cert.pfx
openssl base64 -in cert.pfx
```

2. Update PRIVATE_KEY as a secret in Key Vault to the newly generated private key.

3. Update PRIVATE_KEY_PASSWORD as a secret in Key Vault if the value is different.

4. Store the public certificate as a secret (it is already base64-encoded) in Key Vault. Include the BEGIN and END certificate sections. For no downtime, leave the previous certificate as a secret but add/replace another slot with the new public certificate. You can have up to 4 certificates for validation.

    For instance, in the example under Criteria, you defined both PUBLIC_CERT_0 and PUBLIC_CERT_1, but PUBLIC_CERT_1 returned a 404 because you only had 1 certificate in Key Vault. You could now put that secret into Key Vault. When it came time to rotate again, you could replace PUBLIC_CERT_0 with the new certificate (certificates based on that previous PRIVATE_KEY have probably long been expired).

5. Instruct the auth service to clear it's certificate cache. This should allow auth service to offer the new public certificate for validation.

Example:

```bash
# clear the public keys on the server
curl -i -X POST -F "password=my-command-password" -F "scope=public" https://auth.plasne.com/cas/clear-server-cache

# verify the certificates now show up
curl -i https://auth.plasne.com/cas/keys
```

6. Instruct your API service to clear the openid-configuration cache. This should allows the API service to see the new public certificate.

Example:

```bash
# use the tools to issue an admin token
dotnet run issue-token -o 123 -n "Peter Lasne" -e pelasne@microsoft.com -r admin -d 60 --xsrf secret

# clear cache by providing admin credentials (use the token in the cookie)
curl -i -X POST -F "scope=public" --cookie "user=ey...fk" --header "X-XSRF-TOKEN: secret" https://api.plasne.com/cas/clear-client-cache

# get a list of all certificate thumbprints that are now used for validation
curl -i --cookie "user=ey...fk" --header "X-XSRF-TOKEN: secret" https://api.plasne.com/cas/validation-thumbprints
```

7. Instruct your auth service to clear the signing-key cache. This should allow the auth service to issue tokens using the new private key.

```bash
curl -i -X POST -F "password=my-secret-password" -F "scope=private" https://auth.plasne.com/cas/clear-server-cache
```
