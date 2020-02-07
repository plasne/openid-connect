# Configuration

There can be a lot of configuration settings, if you find that cumbersome, you might consider using Azure App Configuration.

This section will use the following definitions:

-   "server" refers to the service that is issuing authorization tokens.

-   "client" refers to the service that is validating tokens and accepting them as authorization.

-   "web" refers to the service that is hosting the static web assets.

## Minimum Local-Debug Server Configuration

The following shows a sample of a minimum configuration when running on localhost in an insecure manner...

```
USE_INSECURE_DEFAULTS=true
TENANT_ID=00000000-0000-0000-0000-000000000000
CLIENT_ID=00000000-0000-0000-0000-000000000000
```

## Minimum Deployed Server Configuration

The following shows a sample of a minimum configuration when deployed...

```
SERVER_HOST_URL=http://auth.plasne.com
CLIENT_HOST_URL=http://api.plasne.com
WEB_HOST_URL=http://web.plasne.com
TENANT_ID=00000000-0000-0000-0000-000000000000
CLIENT_ID=00000000-0000-0000-0000-000000000000
PRIVATE_KEY=https://sample.vault.azure.net/private_key
PRIVATE_KEY_PASSWORD=https://sample.vault.azure.net/private_key_pw
PUBLIC_CERT_PREFIX=https://sample.vault.azure.net/public_cert_prefix
```

You can use DEFAULT_HOST_URL to act as a default for SERVER_HOST_URL, CLIENT_HOST_URL, and WEB_HOST_URL. In the rare event that you are hosting multiple roles on the same domain, this could save you a couple of settings.

## Minimum Local-Debug Client Configuration

You can startup a local client with even fewer settings...

```
USE_INSECURE_DEFAULTS=true
```

## Minimum Deployed Client Configuration

For a deployed client, you can simply pass the URLs (or DEFAULT_HOST_URL if appropriate)...

```
SERVER_HOST_URL=http://auth.plasne.com
CLIENT_HOST_URL=http://api.plasne.com
WEB_HOST_URL=http://web.plasne.com
```

## Minimum Deployed Configuration on Azure App Configuration

The following sample settings could be set by environment variable for the server...

```
APPCONFIG=pelasne-auth-config
CONFIG_KEYS=sample:auth:dev:*, sample:common:dev:*
```

And for the client...

```
APPCONFIG=pelasne-auth-config
CONFIG_KEYS=sample:api:dev:*, sample:common:dev:*
```

And then the following settings in Azure App Configuration...

```
sample:common:dev:SERVER_HOST_URL=http://auth.plasne.com
sample:common:dev:CLIENT_HOST_URL=http://api.plasne.com
sample:common:dev:WEB_HOST_URL=http://web.plasne.com
sample:auth:dev:TENANT_ID=00000000-0000-0000-0000-000000000000
sample:auth:dev:CLIENT_ID=00000000-0000-0000-0000-000000000000
sample:auth:dev:PRIVATE_KEY=https://sample.vault.azure.net/private_key
sample:auth:dev:PRIVATE_KEY_PASSWORD=https://sample.vault.azure.net/private_key_pw
sample:auth:dev:PUBLIC_CERT_PREFIX=https://sample.vault.azure.net/public_cert_prefix
```
