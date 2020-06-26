# Version 4.1.0

Version 4.1.0 includes a few minor changes to allow Istio to be used to validate tokens issued from CasAuth.

## BUGFIX - "n"

Unfortunately there has been a persistent bug since the first version of this product. The auth server's /cas/keys endpoint includes the modulus of the certificate as property "n". This was supposed to be Base64 URL encoded, but it was simply Base64 encoded. This has never been an issue because all validators so far have used the "x5c" property instead of modulus and exponent, but it is fixed now.

## sub

To allow Istio to pass authorization based on having a request principal a "sub" (subject) claim was needed. CasAuth now creates a "sub" claim from "email", "oid", or "sub" (in that order) from the id_token. If none of those are present, "sub" will not be added.
