
using System;
using System.Collections.Generic;
using System.Linq;

namespace CasAuth
{

    public static class UriExtensions
    {
        public static Uri Append(this Uri uri, params string[] paths)
        {
            return new Uri(paths.Aggregate(uri.AbsoluteUri, (current, path) => string.Format("{0}/{1}", current.TrimEnd('/'), path.TrimStart('/'))));
        }
    }

    public static class CasEnv
    {

        public static string Proxy
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("PROXY") ??
                    System.Environment.GetEnvironmentVariable("HTTPS_PROXY") ??
                    System.Environment.GetEnvironmentVariable("HTTP_PROXY");
            }
        }

        public static bool UseInsecureDefaults
        {
            get
            { // default is false
                string v = System.Environment.GetEnvironmentVariable("USE_INSECURE_DEFAULTS");
                if (string.IsNullOrEmpty(v)) return false;
                string[] positive = new string[] { "yes", "true", "1" };
                return (positive.Contains(v.ToLower()));
            }
        }

        public static string ClientHostUrl
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("CLIENT_HOST_URL");
                if (string.IsNullOrEmpty(s) && UseInsecureDefaults) return "http://localhost:5200";
                return s;
            }
        }

        public static string ServerHostUrl
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("SERVER_HOST_URL");
                if (string.IsNullOrEmpty(s) && UseInsecureDefaults) return "http://localhost:5100";
                return s;
            }
        }

        public static bool IsLocalhost
        {
            get
            {
                return ClientHostUrl.Contains("/localhost:", StringComparison.InvariantCultureIgnoreCase)
                    && ServerHostUrl.Contains("/localhost:", StringComparison.InvariantCultureIgnoreCase);
            }
        }

        public static bool IsHttps
        {
            get
            {
                return ClientHostUrl.Contains("https://", StringComparison.InvariantCultureIgnoreCase)
                    && ServerHostUrl.Contains("https://", StringComparison.InvariantCultureIgnoreCase);
            }
        }

        public static string BaseDomain
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("BASE_DOMAIN");
                if (string.IsNullOrEmpty(s))
                {
                    var list = new Stack<char>();
                    string u1 = new Uri(ClientHostUrl).Host;
                    string u2 = new Uri(ServerHostUrl).Host;
                    int max = Math.Min(u1.Length, u2.Length);
                    for (int j = 0; j < max; j++)
                    {
                        string c = u1.Substring(u1.Length - j - 1);
                        if (c == u2.Substring(u2.Length - j - 1))
                        {
                            list.Push(c[0]);
                        }
                        else
                        {
                            break;
                        }
                    }
                    return string.Join("", list.ToArray());
                }
                return s;
            }
        }

        public static string Issuer
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("ISSUER");
                if (string.IsNullOrEmpty(s)) return ServerHostUrl;
                return s;
            }
        }

        public static string Audience
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("AUDIENCE");
                if (string.IsNullOrEmpty(s)) return ClientHostUrl;
                return s;
            }
        }

        public static string WellKnownConfigUrl
        {
            get
            { // generally this should just go with default
                string s = System.Environment.GetEnvironmentVariable("WELL_KNOWN_CONFIG_URL");
                if (string.IsNullOrEmpty(s)) return new Uri(ServerHostUrl).Append("/cas/.well-known/openid-configuration").AbsoluteUri;
                return s;
            }
        }

        public static string ReissueUrl
        {
            get
            { // generally this should just go with default
                string s = System.Environment.GetEnvironmentVariable("REISSUE_URL");
                if (string.IsNullOrEmpty(s)) return new Uri(ServerHostUrl).Append("/cas/reissue").AbsoluteUri;
                return s;
            }
        }

        public static string[] AllowedOrigins
        {
            get
            {
                string origins = System.Environment.GetEnvironmentVariable("ALLOWED_ORIGINS");
                if (string.IsNullOrEmpty(origins))
                {
                    if (UseInsecureDefaults && IsLocalhost)
                    {
                        return new string[] { "http://localhost:5000" };
                    }
                    else if (!string.IsNullOrEmpty(ClientHostUrl))
                    {
                        return new string[] { ClientHostUrl };
                    }
                    else
                    {
                        return new string[] { };
                    }
                }
                return origins.Split(',').Select(id => id.Trim()).ToArray();
            }
        }

        public static bool RequireSecureForCookies
        {
            get
            { // if both client and server are https, then true
                string v = System.Environment.GetEnvironmentVariable("REQUIRE_SECURE_FOR_COOKIES");
                if (string.IsNullOrEmpty(v)) return IsHttps;
                string[] negative = new string[] { "no", "false", "0" };
                return (!negative.Contains(v));
            }
        }

        public static bool RequireHttpOnlyOnUserCookie
        {
            get
            { // default is true
                string v = System.Environment.GetEnvironmentVariable("REQUIRE_HTTPONLY_ON_USER_COOKIE");
                if (string.IsNullOrEmpty(v)) return true;
                string[] negative = new string[] { "no", "false", "0" };
                return (!negative.Contains(v.ToLower()));
            }
        }

        public static bool RequireHttpOnlyOnXsrfCookie
        {
            get
            { // default is false
                string v = System.Environment.GetEnvironmentVariable("REQUIRE_HTTPONLY_ON_XSRF_COOKIE");
                if (string.IsNullOrEmpty(v)) return false;
                string[] positive = new string[] { "yes", "true", "1" };
                return (positive.Contains(v.ToLower()));
            }
        }

        public static bool VerifyTokenInHeader
        {
            get
            { // default is false
                string v = System.Environment.GetEnvironmentVariable("VERIFY_TOKEN_IN_HEADER");
                if (string.IsNullOrEmpty(v)) return false;
                string[] positive = new string[] { "yes", "true", "1" };
                return (positive.Contains(v.ToLower()));
            }
        }

        public static bool VerifyTokenInCookie
        {
            get
            { // default is true
                string v = System.Environment.GetEnvironmentVariable("VERIFY_TOKEN_IN_COOKIE");
                if (string.IsNullOrEmpty(v)) return true;
                string[] negative = new string[] { "no", "false", "0" };
                return (!negative.Contains(v));
            }
        }

        public static bool VerifyXsrfInHeader
        {
            get
            { // default is true
                string v = System.Environment.GetEnvironmentVariable("VERIFY_XSRF_IN_HEADER");
                if (string.IsNullOrEmpty(v)) return true;
                string[] negative = new string[] { "no", "false", "0" };
                return (!negative.Contains(v.ToLower()));
            }
        }

        public static bool VerifyXsrfInCookie
        {
            get
            { // default is false
                string v = System.Environment.GetEnvironmentVariable("VERIFY_XSRF_IN_COOKIE");
                if (string.IsNullOrEmpty(v)) return false;
                string[] positive = new string[] { "yes", "true", "1" };
                return (positive.Contains(v.ToLower()));
            }
        }

        public static string UserCookieName
        {
            get
            { // generally this should just go with default
                string v = System.Environment.GetEnvironmentVariable("USER_COOKIE_NAME");
                if (string.IsNullOrEmpty(v)) return "user";
                return v;
            }
        }

        public static string RoleForAdminFunctions
        {
            get
            { // generally this should just go with default
                string v = System.Environment.GetEnvironmentVariable("ROLE_FOR_ADMIN_FUNCTIONS");
                if (string.IsNullOrEmpty(v)) return "admin";
                return v;
            }
        }

        public static string TenantId
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("TENANT_ID");
            }
        }

        public static string ClientId
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("CLIENT_ID");
            }
        }

        public static string ClientSecret
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("CLIENT_SECRET");
            }
        }

        public static string TenantIdConfig
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("TENANT_ID_CONFIG");
                if (string.IsNullOrEmpty(s)) return TenantId;
                return s;
            }
        }

        public static string ClientIdConfig
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("CLIENT_ID_CONFIG");
                if (string.IsNullOrEmpty(s)) return ClientId;
                return s;
            }
        }

        public static string ClientSecretConfig
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("CLIENT_SECRET_CONFIG");
                if (string.IsNullOrEmpty(s)) return ClientSecret;
                return s;
            }
        }

        public static string TenantIdGraph
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("TENANT_ID_GRAPH");
                if (string.IsNullOrEmpty(s)) return TenantId;
                return s;
            }
        }

        public static string ClientIdGraph
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("CLIENT_ID_GRAPH");
                if (string.IsNullOrEmpty(s)) return ClientId;
                return s;
            }
        }

        public static string ClientSecretGraph
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("CLIENT_SECRET_GRAPH");
                if (string.IsNullOrEmpty(s)) return ClientSecret;
                return s;
            }
        }


        public static string TenantIdVault
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("TENANT_ID_VAULT");
                if (string.IsNullOrEmpty(s)) return TenantId;
                return s;
            }
        }

        public static string ClientIdVault
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("CLIENT_ID_VAULT");
                if (string.IsNullOrEmpty(s)) return ClientIdConfig;
                return s;
            }
        }

        public static string ClientSecretVault
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("CLIENT_SECRET_VAULT");
                if (string.IsNullOrEmpty(s)) return ClientSecretConfig;
                return s;
            }
        }

        public static string Authority
        {
            get
            { // generally this should just go with default
                string s = System.Environment.GetEnvironmentVariable("AUTHORITY");
                if (string.IsNullOrEmpty(s) && !string.IsNullOrEmpty(TenantId)) return $"https://login.microsoftonline.com/{TenantId}";
                return s;
            }
        }

        public static string RedirectUri
        {
            get
            { // generally this should just go with default
                string s = System.Environment.GetEnvironmentVariable("REDIRECT_URI");
                if (string.IsNullOrEmpty(s)) return new Uri(ServerHostUrl).Append("/cas/token").AbsoluteUri;
                return s;
            }
        }

        public static string DefaultRedirectUrl
        {
            get
            { // generally this should be set because the default is unlikely to be right
                // note: it is not required because they /authorize request can specify a callback
                string s = System.Environment.GetEnvironmentVariable("DEFAULT_REDIRECT_URL");
                if (string.IsNullOrEmpty(s)) return ClientHostUrl;
                return s;
            }
        }

        public static string[] ApplicationIds
        {
            get
            { // used for determining roles
                string appId = System.Environment.GetEnvironmentVariable("APPLICATION_ID");
                if (string.IsNullOrEmpty(appId)) return new string[] { };
                return appId.Split(',').Select(id => id.Trim()).ToArray();
            }
        }

        public static string DomainHint
        {
            get
            { // very optional
                return System.Environment.GetEnvironmentVariable("DOMAIN_HINT");
            }
        }

        public static string KeyvaultClientSecretUrl
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("KEYVAULT_CLIENT_SECRET_URL");
            }
        }

        public static int JwtDuration
        {
            get
            {
                // value is provided in minutes
                string duration = System.Environment.GetEnvironmentVariable("JWT_DURATION");
                if (int.TryParse(duration, out int result))
                {
                    return result;
                }
                else
                {
                    return 60 * 4; // 4 hours
                }
            }
        }

        public static int JwtServiceDuration
        {
            get
            {
                // value is provided in minutes
                string duration = System.Environment.GetEnvironmentVariable("JWT_SERVICE_DURATION");
                if (int.TryParse(duration, out int result))
                {
                    return result;
                }
                else
                {
                    return JwtDuration;
                }
            }
        }

        public static int JwtMaxDuration
        {
            get
            {
                // value is provided in minutes
                // only needed for AutoRenewJwt
                string duration = System.Environment.GetEnvironmentVariable("JWT_MAX_DURATION");
                if (int.TryParse(duration, out int result))
                {
                    return result;
                }
                else
                {
                    return 60 * 24 * 7; // 7 days, 0 = forever
                }
            }
        }

        public static string PublicKeysUrl
        {
            get
            { // typically this should left default
                string s = System.Environment.GetEnvironmentVariable("PUBLIC_KEYS_URL");
                if (string.IsNullOrEmpty(s)) return new Uri(ServerHostUrl).Append("/cas/keys").AbsoluteUri;
                return s;
            }
        }

        public static bool RequireUserEnabledOnReissue
        {
            get
            { // default is true
                string v = System.Environment.GetEnvironmentVariable("REQUIRE_USER_ENABLED_ON_REISSUE");
                if (string.IsNullOrEmpty(v)) return true;
                string[] negative = new string[] { "no", "false", "0" };
                return (!negative.Contains(v.ToLower()));
            }
        }

        public static string CommandPassword
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("COMMAND_PASSWORD");
            }
        }

        public static string KeyvaultCommandPasswordUrl
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("KEYVAULT_COMMAND_PASSWORD_URL");
            }
        }

        public static string PrivateKey
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("PRIVATE_KEY");
                if (string.IsNullOrEmpty(s) && string.IsNullOrEmpty(KeyvaultPrivateKeyUrl) && UseInsecureDefaults)
                {
                    // this is intended to allow the application to work for localhost debug only
                    return "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";
                }
                return s;
            }
        }

        public static string KeyvaultPrivateKeyUrl
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("KEYVAULT_PRIVATE_KEY_URL");
            }
        }

        public static string PrivateKeyPassword
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("PRIVATE_KEY_PASSWORD");
                if (string.IsNullOrEmpty(s) && string.IsNullOrEmpty(KeyvaultPrivateKeyPasswordUrl) && UseInsecureDefaults)
                {
                    // this is intended to allow the application to work for localhost debug only
                    return "secret";
                }
                return s;
            }
        }

        public static string KeyvaultPrivateKeyPasswordUrl
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("KEYVAULT_PRIVATE_KEY_PASSWORD_URL");
            }
        }

        public static string[] PublicCertificates
        {
            get
            {
                var list = new List<string>();
                for (int i = 0; i < 4; i++)
                {
                    string s = System.Environment.GetEnvironmentVariable($"PUBLIC_CERT_{i}");
                    if (!string.IsNullOrEmpty(s)) list.Add(s);
                }
                if (list.Count < 1 && string.IsNullOrEmpty(KeyvaultPublicCertPrefixUrl) && UseInsecureDefaults)
                {
                    // this is intended to allow the application to work for localhost debug only
                    list.Add("-----BEGIN CERTIFICATE-----MIIEljCCAn4CCQDsm/eax4C4aTANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJVUzAeFw0yMDAxMTEwMDQ5MzRaFw0yMTAxMTAwMDQ5MzRaMA0xCzAJBgNVBAYTAlVTMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA7QJ2KzBfDd/iIU6y37uyf2V3YeXKQd8QyF5j/L/UQTROk9kSc0VdLGnbeYFdk2EJCb5OxhdJ7vKflpz270DmcAs22LfMxNn4eRWr9xVrpAKjASKy1WQFmRpa4b7PJairHJt9Ug4qJgB8FWPeZzehTClyit0RuoJNWOZZxH+1zyJhkYLcxWglvijwRkBg2+AB/6p2CszVHKB7ZksVXOy3uGpr8ZDP3p0Ak9p1GqsjACIC48TFUMbj1vSFimkOexx24Ji/PKNtQxZzBNOtGNCPDFWgtDZHs2aVm7ddceFvpW0YgxrJ/DjGpIUAZdT3dsI5alG7OD7UxVjWMORD4RQi/hYRgKkW/o5mv7xW9pJqTiOOaiNifIyfYJJgBq8WdJolQV977HHnSIblFlQK2ZzNNlsf+vIzBzC+98NcptgJ4wjmQ1ALz9jGGsG06qVula2PLkPchXBm5toN/y8LF5mfJcjYFLAcFyS+YKLnVj2ro1R3V+xTFG6ytg8AajUsQfLSCPMa1jvdGHP4/NwhpDAHb6lUVC5pjBx0jtZn/Rl6ynuN1sxmLBC9UAUCG9NP+5JZC7lYV+v1MPlrUNqFsFO0BGqZ+AiQU3PBCBVdRbVuYO7HaOJszQSbyW0cAafS5uuxQzgGA8/aHeuqajweBw46Qrh+2Odwz6+Ou5mt7pofp6sCAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAqej5HxwsK5hBZKhWdAIAQqZdSfn16TvJr1SYM9VYqum0sJBvdwgruVKqRIRyLLS7ZbBTpyNkznEM9GYDTacuV5lDUewVwXV2KL2a/LtK0DF9qinCbyqdCMeTr/Vt9JS9XyBfRi3sPZljzp+EchLh6k2pqDA17fzUjmisEjuka5CFSBOpt5Zzl1rY9a7Et8Jk4tUuiPDlRV3WVCLM0VUX3AIo7Fh/DAo0Afsklbb70YpEMqgK43dAmeVCDQtCweHM8j45HVX5CMp8nJOSZ1COvbbstqgMeRYgL+ESo+law0tU0ZzjiIM1pkNwUSgni5JBMDzWSbb1XgbPOVbKN4Wpp76mb4PmKL5kecy4twCh5pgKU7/dxG3l8fOMVvwvxynS6wawg+I6cb7Xjf+IQ1XfNLptBqG4gk9wbztbdCfVJyDDsOc2ZpmgLWayt5Up51snc2f1lTOa9OPnJibrRTtYkG9fp18FHZMM+ug1ibcxuMPaUcobxYa2tEjIFfWymxLb4LsQcxEkPq4kKKhueRNJPPfWqsvfQRNcD0vKlnWTdKWtYzlb3ay91fEjvuHZpKJgaLP0c4JEI0WFViKOeQmhor6LvcsTBXYAgOBNaDP28a6AhW8/OvLMC7CCkAKx+JVatZwnNYOemXLfPMTZA5whACZAhoT3on97RjWkekTRnys=-----END CERTIFICATE-----");
                }
                return list.ToArray();
            }
        }

        public static string KeyvaultPublicCertPrefixUrl
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("KEYVAULT_PUBLIC_CERT_PREFIX_URL");
            }
        }

        public static string[] KeyvaultPublicCertificateUrls
        {
            get
            {
                var list = new List<string>();
                string url = KeyvaultPublicCertPrefixUrl;
                if (!string.IsNullOrEmpty(url))
                {
                    for (int i = 0; i < 4; i++)
                    {
                        list.Add($"{url}{i}");
                    }
                }
                return list.ToArray();
            }
        }

    }

}