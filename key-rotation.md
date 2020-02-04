# Key Rotation

You can only have 1 signing key, but you can have up to 4 validation certificates. This allows you to seamlessly rotate your signing key while still allowing older keys to be validated for some period of time.

1. Create a new private key, certificate, and PFX file.

```bash
openssl req -x509 -newkey rsa:4096 -keyout privatekey.pem -out certificate.pem -days 365
openssl pkcs12 -export -inkey privatekey.pem -in certificate.pem -out cert.pfx
```

2. Replace the existing PFX signing key with the new one as a base64-encoded secret.

```bash
openssl base64 -in cert.pfx
```

3. If the PFX password has changed, replace the existing PFX password with the new one as a secret.

4. Store the public certificate as a secret (it is already base64-encoded). Include the BEGIN and END certificate sections. The secret should end with a 0, 1, 2, or 3. You might need to replace an existing certificate. You can have up to 4 certificates for validation.

5. Instruct the auth service to clear the validation-certificates cache. This should allow auth service to offer the new public certificate for validation.

Example:

```bash
# clear the cache
curl -i -X POST -d "password=my-command-password&scope=validation-certificates" https://auth.plasne.com/api/auth/clear-cache

# verify the certificates now show up
curl -i https://auth.plasne.com/cas/keys
```

6. Instruct your API service to clear the openid-configuration cache. This should allows the API service to see the new public certificate.

Example:

```bash
# use the tools to issue an admin token
dotnet run issue-token -o 123 -n "Peter Lasne" -e pelasne@microsoft.com -r admin -d 60 --xsrf secret

# clear cache by providing admin credentials (use the token in the cookie)
curl -i -X POST -d "scope=openid-configuration" --cookie "user=ey...fk" --header "X-XSRF-TOKEN: secret" https://api.plasne.com/cas/clear-cache

# get a list of all certificate thumbprints that are now used for validation
curl -i --cookie "user=ey...fk" --header "X-XSRF-TOKEN: secret" https://api.plasne.com/cas/validation-thumbprints
```

7. Instruct your auth service to clear the signing-key cache. This should allow the auth service to issue tokens using the new private key.

```bash
curl -i -X POST -d "password=my-secret-password&scope=signing-key" https://auth.plasne.com/cas/clear-cache
```
