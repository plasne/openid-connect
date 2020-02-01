# Configuration

There are a lot of configuration settings that could be set so you might consider using Azure App Configuration.

This section will use the following definitions:

-   "server" refers to the service that is issuing authorization tokens.

-   "client" refers to the service that is validating tokens and accepting them as authorization.

## Minimum Local-Debug Server Configuration

The following shows a sample of a minimum configuration when running on localhost in an insecure manner.

```
USE_INSECURE_DEFAULTS=true
TENANT_ID=00000000-0000-0000-0000-000000000000
CLIENT_ID=00000000-0000-0000-0000-000000000000
```

## Minimum Production Server Configuration

The following shows a sample of a minimum configuration

```
SERVER_HOST_URL=http://auth.plasne.com
CLIENT_HOST_URL=http://api.plasne.com
WEB_HOST_URL=http://web.plasne.com
TENANT_ID=00000000-0000-0000-0000-000000000000
CLIENT_ID=00000000-0000-0000-0000-000000000000
KEYVAULT_PRIVATE_KEY_URL=https://private_key
KEYVAULT_PRIVATE_KEY_PASSWORD_URL=https://private_key_pw
KEYVAULT_PUBLIC_CERT_PREFIX_URL=https://public_cert_prefix
```

## Minimum Client Configuration

SERVER_HOST_URL=http://auth.plasne.com
CLIENT_HOST_URL=http://api.plasne.com
