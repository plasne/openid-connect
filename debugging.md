# Debugging Locally

A common configuration for running locally is...

```
PROXY=http://my_proxy
LOG_LEVEL=Debug
USE_INSECURE_DEFAULTS=true
TENANT_ID=00000000-0000-0000-0000-000000000000
CLIENT_ID=00000000-0000-0000-0000-000000000000
```

One warning, at least in Chrome and Firefox, cookies without the Secure flag will not replace cookies with the Secure flag. Therefore, if you run with REQUIRE_SECURE_FOR_COOKIES with the default of "true" and then change it to "false", cookies could have been created that wouldn't get replaced and you will get errors that the state and nonce values don't match. You can manually delete those cookies should that happen.

If it is easier to test, you might also consider the following, which allows session_tokens in the header or cookie and does not validate XSRF. Note that you should not run this configuration in production.

```
VERIFY_TOKEN_IN_COOKIE=true
VERIFY_TOKEN_IN_HEADER=true
VERIFY_XSRF_IN_COOKIE=false
VERIFY_XSRF_IN_HEADER=false
```
