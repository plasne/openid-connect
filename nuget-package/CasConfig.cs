using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using NetBricks;

namespace CasAuth
{

    public static class UriExtensions
    {
        public static Uri Append(this Uri uri, params string[] paths)
        {
            return new Uri(paths.Aggregate(uri.AbsoluteUri, (current, path) => string.Format("{0}/{1}", current.TrimEnd('/'), path.TrimStart('/'))));
        }
    }

    public class CasConfig : Config
    {
        public CasConfig(
            ILogger<CasConfig> logger,
            IAccessTokenFetcher accessTokenFetcher,
            IHttpClientFactory httpClientFactory
        ) : base(logger, accessTokenFetcher, httpClientFactory)
        { }

        public override AuthTypes AuthType(string type = null, Func<string, string> map = null)
        {
            if (map == null) map = str =>
            {
                switch (str)
                {
                    case "app":
                    case "application":
                    case "service":
                    case "service_principal":
                    case "service-principal":
                    case "service principal":
                        return AuthTypes.Service.ToString();
                    default:
                        return AuthTypes.Token.ToString();
                }
            };
            return base.AuthType(type, map);
        }

        /// <summary>
        /// [OPTIONAL] To support proxy on all HttpClient connections.
        /// </summary>
        public static string Proxy
        {
            get => GetOnce("PROXY", "HTTPS_PROXY", "HTTP_PROXY");
        }

        /// <summary>
        /// [OPTIONAL, default: false] This can be enabled for a local debug scenarios where you don't want to set:
        /// CLIENT_HOST_URL, SERVER_HOST_URL, PRIVATE_KEY, PRIVATE_KEY_PASSWORD, and PUBLIC_CERT_0.
        /// Never run this production!
        /// </summary>
        public static bool UseInsecureDefaults
        {
            get => GetOnce("USE_INSECURE_DEFAULTS").AsBool(() => false);
        }

        /// <summary>
        /// [OPTIONAL] If you have multiple roles (Auth, API, Web, etc.) on the same URL, you might specify
        /// this setting which will act as a default for CLIENT_HOST_URL, SERVER_HOST_URL, and WEB_HOST_URL.
        /// </summary>
        public static string DefaultHostUrl
        {
            get => GetOnce("DEFAULT_HOST_URL");
        }

        /// <summary>
        /// [OPTIONAL] This denotes the URL of the API service that is validating authentication tokens.
        /// If you have more than one, just specify one of them.
        /// Specifying this and SERVER_HOST_URL allows defaults to be calculated for:
        /// ALLOWED_ORIGINS, BASE_DOMAIN, AUDIENCE, ISSUER, DEFAULT_REDIRECT_URL, REQUIRE_SECURE_FOR_COOKIES,
        /// WELL_KNOWN_CONFIG_URL, REDIRECT_URL, and REISSUE_URL.
        /// </summary>
        public static string ClientHostUrl
        {
            get => GetOnce("CLIENT_HOST_URL", "DEFAULT_HOST_URL").AsString(() =>
            {
                if (UseInsecureDefaults) return "http://localhost:5200";
                return null;
            });
        }

        /// <summary>
        /// [OPTIONAL] This denotes the URL of the Authentication service that is issuing authentication tokens.
        /// Specifying this and CLIENT_HOST_URL allows defaults to be calculated for:
        /// ALLOWED_ORIGINS, BASE_DOMAIN, AUDIENCE, ISSUER, DEFAULT_REDIRECT_URL, REQUIRE_SECURE_FOR_COOKIES,
        /// WELL_KNOWN_CONFIG_URL, REDIRECT_URL, and REISSUE_URL.
        /// </summary>
        public static string ServerHostUrl
        {
            get => GetOnce("SERVER_HOST_URL", "DEFAULT_HOST_URL").AsString(() =>
            {
                if (UseInsecureDefaults) return "http://localhost:5100";
                return null;
            });
        }

        /// <summary>
        /// [OPTIONAL] This denotes the URL of the web front end. Specifying this allows for better defaults
        /// to be calculated for: ALLOWED_ORIGINS and DEFAULT_REDIRECT_URL.
        /// </summary>
        public static string WebHostUrl
        {
            get => GetOnce("WEB_HOST_URL", "DEFAULT_HOST_URL").AsString(() =>
            {
                if (UseInsecureDefaults) return "http://localhost:5000";
                return null;
            });
        }

        /// <summary>
        /// [OPTIONAL, default: *derived] "true" if both CLIENT_HOST_URL and SERVER_HOST_URL use a protocol of "https".
        /// This also defaults to "true" if CLIENT_HOST_URL or SERVER_HOST_URL is not set.
        /// </summary>
        public static bool IsHttps
        {
            get => GetOnce("IS_HTTPS").AsBool(() =>
            {
                if (string.IsNullOrEmpty(ClientHostUrl)) return true;
                if (string.IsNullOrEmpty(ServerHostUrl)) return true;
                return ClientHostUrl.Contains("https://", StringComparison.InvariantCultureIgnoreCase)
                    && ServerHostUrl.Contains("https://", StringComparison.InvariantCultureIgnoreCase);
            });
        }

        /// <summary>
        /// [OPTIONAL, default: *derived] Allows you to specify the domain of all cookies so they can be shared when the client and
        /// server are on different URLs. Typically, just set CLIENT_HOST_URL and SERVER_HOST_URL and this can be
        /// calculated.
        /// </summary>
        public static string BaseDomain(HttpRequest request = null)
        {
            string s = GetOnce("BASE_DOMAIN");

            // look for variables
            if (string.Compare(s, "$RequestDomain", StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                s = (request != null) ? request.Host.Host : "$RequestDomain";
            }
            else if (string.Compare(s, "$RequestSubdomain", StringComparison.InvariantCultureIgnoreCase) == 0)
            {
                if (request != null)
                {
                    var parts = request.Host.Host.Split(".").ToList();
                    if (parts.Count > 1)
                    {
                        parts.RemoveAt(0);
                        s = string.Join(".", parts);
                    }
                    else
                    {
                        s = request.Host.Host; // do domain, if there is no subdomain
                    }
                }
                else
                {
                    s = "$RequestSubdomain";
                }
            }

            // use commonality between CLIENT_HOST_URL and SERVER_HOST_URL
            if (string.IsNullOrEmpty(s) && !string.IsNullOrEmpty(ClientHostUrl) && !string.IsNullOrEmpty(ServerHostUrl))
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
                s = string.Join("", list.ToArray());
            }

            // add the prefixed . just in case the browser is old enough to require it
            //if (!string.IsNullOrEmpty(s) && s.Substring(0, 1) != "$" && s.Substring(0, 1) != ".") s = "." + s;

            return s;
        }

        /// <summary>
        /// [OPTIONAL, default: SERVER_HOST_URL] Allows you to specify the "iss" in the JWT that is issued by the server component.
        /// Typically just set SERVER_HOST_URL and that URL will be used.
        /// </summary>
        public static string Issuer
        {
            get => GetOnce("ISSUER").AsString(() => ServerHostUrl);
        }

        /// <summary>
        /// [OPTIONAL, default: CLIENT_HOST_URL] Allows you to specify the "aud" in the JWT that is issued by the server component.
        /// Typically just set CLIENT_HOST_URL and that URL will be used.
        /// </summary>
        public static string Audience
        {
            get => GetOnce("AUDIENCE").AsString(() => ClientHostUrl);
        }

        /// <summary>
        /// [OPTIONAL] This allows you to specify the URL for the well-known-config endpoint.
        /// Typically just set SERVER_HOST_URL and that URL will be calculated.
        /// </summary>
        public static string WellKnownConfigUrl
        {
            get => GetOnce("WELL_KNOWN_CONFIG_URL").AsString(() =>
            {
                if (!string.IsNullOrEmpty(ServerHostUrl)) return new Uri(ServerHostUrl).Append("/cas/.well-known/openid-configuration").AbsoluteUri;
                return null;
            });
        }

        /// <summary>
        /// [OPTIONAL] This allows you to specify the URL for the public keys endpoint.
        /// Typically just set SERVER_HOST_URL and that URL will be calculated.
        /// </summary>
        public static string PublicKeysUrl
        {
            get => GetOnce("PUBLIC_KEYS_URL").AsString(() =>
            {
                if (!string.IsNullOrEmpty(ServerHostUrl)) return new Uri(ServerHostUrl).Append("/cas/keys").AbsoluteUri;
                return null;
            });
        }

        /// <summary>
        /// [OPTIONAL] This allows you to specify the URL for the reissue endpoint.
        /// Typically just set SERVER_HOST_URL and that URL will be calculated.
        /// </summary>
        public static string ReissueUrl
        {
            get
            {
                string s = GetOnce("REISSUE_URL").AsString(() =>
                {
                    if (!string.IsNullOrEmpty(ServerHostUrl)) return new Uri(ServerHostUrl).Append("/cas/reissue").AbsoluteUri;
                    return null;
                });
                string[] negative = new string[] { "no", "false", "0" };
                if (negative.Contains(s?.ToLower())) return null;
                return s;
            }
        }

        /// <summary>
        /// [OPTIONAL] This allows you to specify a common delimited list of domain names that will be given
        /// a CORS response. If you have WEB_HOST_URL, it will default to that, otherwise it will use CLIENT_HOST_URL.
        /// </summary>
        public static string[] AllowedOrigins
        {
            get => GetOnce("ALLOWED_ORIGINS").AsArray(() =>
            {
                if (!string.IsNullOrEmpty(WebHostUrl))
                {
                    return new string[] { WebHostUrl };
                }
                else if (!string.IsNullOrEmpty(ClientHostUrl))
                {
                    return new string[] { ClientHostUrl };
                }
                else
                {
                    return new string[] { };
                }
            });
        }

        /// <summary>
        /// [OPTIONAL] This allows you to control where cookies is issued with the "secure" flag.
        /// Typically just set CLIENT_HOST_URL and SERVER_HOST_URL and this will be set automatically 
        /// (true if both are https protocol, false otherwise).
        /// </summary>
        public static bool RequireSecureForCookies
        {
            get => GetOnce("REQUIRE_SECURE_FOR_COOKIES").AsBool(() => IsHttps);
        }

        /// <summary>
        /// [OPTIONAL, default: true] This can be set to "false" for certain authentication scenarios, but it is very
        /// uncommon, and can easily be a security risk.
        /// </summary>
        public static bool RequireHttpOnlyOnUserCookie
        {
            get => GetOnce("REQUIRE_HTTPONLY_ON_USER_COOKIE").AsBool(() => true);
        }

        /// <summary>
        /// [OPTIONAL, default: false] This can be set to "true" for certain authentication scenarios, but it is very
        /// uncommon, though not insecure.
        /// </summary>
        public static bool RequireHttpOnlyOnXsrfCookie
        {
            get => GetOnce("REQUIRE_HTTPONLY_ON_XSRF_COOKIE").AsBool(() => false);
        }

        /// <summary>
        /// [OPTIONAL, default: lax] This determines the SameSite setting for the "user" and "XSRF-TOKEN" cookies.
        /// This could also be set to "none" or "strict". "lax" is required for some browsers to read the XSRF-TOKEN
        /// cookie from a subdomain.
        /// </summary>
        public static SameSiteMode SameSite
        {
            get => GetOnce("SAME_SITE").AsEnum<SameSiteMode>(() => SameSiteMode.Lax);
        }

        /// <summary>
        /// [OPTIONAL, default: false] This can be set to "true" for certain authentication scenarios, but it is very
        /// uncommon, and can easily be a security risk.
        /// </summary>
        public static bool VerifyTokenInHeader
        {
            get => GetOnce("VERIFY_TOKEN_IN_HEADER").AsBool(() => false);
        }

        /// <summary>
        /// [OPTIONAL, default: true] This can be set to "false" for certain authentication scenarios, but it is very
        /// uncommon, and can easily be a security risk.
        /// </summary>
        public static bool VerifyTokenInCookie
        {
            get => GetOnce("VERIFY_TOKEN_IN_COOKIE").AsBool(() => true);
        }

        /// <summary>
        /// [OPTIONAL, default: true] This can be set to "false" for certain authentication scenarios, but it is very
        /// uncommon, and can easily be a security risk.
        /// </summary>
        public static bool VerifyXsrfInHeader
        {
            get => GetOnce("VERIFY_XSRF_IN_HEADER").AsBool(() => true);
        }

        /// <summary>
        /// [OPTIONAL, default: false] This can be set to "true" for certain authentication scenarios, but it is very
        /// uncommon, and can easily be a security risk.
        /// </summary>
        public static bool VerifyXsrfInCookie
        {
            get => GetOnce("VERIFY_XSRF_IN_COOKIE").AsBool(() => false);
        }

        /// <summary>
        /// [OPTIONAL, default: user] This allows you to control the name of the cookie that is issued for the
        /// user's session. Typically, just leave it as "user".
        /// </summary>
        public static string UserCookieName
        {
            get => GetOnce("USER_COOKIE_NAME").AsString(() => "user");
        }

        /// <summary>
        /// [OPTIONAL, default: admin] This allows you to specify the name of the role that should be used for
        /// administration. Typically, just leave it as "user".
        /// </summary>
        public static string RoleForAdmin
        {
            get => GetOnce("ROLE_FOR_ADMIN").AsString(() => "admin");
        }

        /// <summary>
        /// [OPTIONAL, default: service] This allows you to specify the name of the role that should be used for
        /// service accounts. Typically, just leave it as "service".
        /// </summary>
        public static string RoleForService
        {
            get => GetOnce("ROLE_FOR_SERVICE").AsString(() => "service");
        }

        /// <summary>
        /// [OPTIONAL] This allows you to specify the Azure Active Directory Tenant ID to use for authentication.
        /// If you do not specify this, you need to specify AUTHORITY. You also require this on the server and/or
        /// client if you are using AUTH_TYPE=app.
        /// </summary>
        public static string AzureTenantId
        {
            get => GetOnce("AZURE_TENANT_ID", "TENANT_ID");
        }

        /// <summary>
        /// [REQUIRED (server)] This allows you to specify the Client ID that will be used for the /authorize endpoint,
        /// AuthCode, and AUTH_TYPE=app. You might also specify specific options for
        /// CLIENT_ID_CONFIG, CLIENT_ID_GRAPH, and CLIENT_ID_VAULT for AUTH_TYPE=app only (you still need).
        /// CLIENT_ID for /authorize and AuthCode.
        /// </summary>
        public static string AzureClientId
        {
            get => GetOnce("AZURE_CLIENT_ID", "CLIENT_ID");
        }

        /// <summary>
        /// [OPTIONAL] This allows you to specify the Client Secret that will be used for AuthCode and/or AUTH_TYPE=app.
        /// If you do not need those features, this is not required. You might also specify specific options for
        /// CLIENT_SECRET_CONFIG, CLIENT_SECRET_GRAPH, and CLIENT_SECRET_VAULT.
        /// </summary>
        public async Task<string> AzureClientSecret(string type = null)
        {

            // determine the key to use
            var key = (type == null) ? "AZURE_CLIENT_SECRET" : $"AZURE_CLIENT_SECRET_{type.ToUpper()}";

            // check the cache
            if (GetFromCache<string>(key, out string val)) return val;

            // look for the value
            val = string.IsNullOrEmpty(type)
                ? GetOnce("AZURE_CLIENT_SECRET", "CLIENT_SECRET")
                : GetOnce(
                    $"AZURE_CLIENT_SECRET_{type.ToUpper()}",
                    $"CLIENT_SECRET_{type.ToUpper()}",
                    "AZURE_CLIENT_SECRET",
                    "CLIENT_SECRET"
                );

            // resolve key-vault links
            val = await GetFromKeyVault(val);

            // add to the cache
            AddToCache(key, val);
            return val;

        }

        /// <summary>
        /// This gets an Azure Tenant Id from one of the following in this order: AZURE_TENANT_ID_type, TENANT_ID_type,
        /// AZURE_TENANT_ID, TENANT_ID.
        /// </summary>
        public override string TenantId(string type = null)
        {
            if (string.IsNullOrEmpty(type))
            {
                return GetOnce("AZURE_TENANT_ID", "TENANT_ID");
            }
            else
            {
                return GetOnce(
                    $"AZURE_TENANT_ID_{type.ToUpper()}",
                    $"TENANT_ID_{type.ToUpper()}",
                    "AZURE_TENANT_ID",
                    "TENANT_ID"
                );
            }
        }

        /// <summary>
        /// This gets an Azure Client Id from one of the following in this order: AZURE_CLIENT_ID_type, CLIENT_ID_type,
        /// AZURE_CLIENT_ID, CLIENT_ID.
        /// </summary>
        public override string ClientId(string type = null)
        {
            if (string.IsNullOrEmpty(type))
            {
                return GetOnce("AZURE_CLIENT_ID", "CLIENT_ID");
            }
            else
            {
                return GetOnce(
                    $"AZURE_CLIENT_ID_{type.ToUpper()}",
                    $"CLIENT_ID_{type.ToUpper()}",
                    "AZURE_CLIENT_ID",
                    "CLIENT_ID"
                );
            }
        }

        /// <summary>
        /// This gets an Azure Client Secret from one of the following in this order: AZURE_CLIENT_SECRET_type,
        /// CLIENT_SECRET_type, AZURE_CLIENT_ID, CLIENT_ID.
        /// </summary>
        public override Task<string> ClientSecret(string type = null)
        {
            return AzureClientSecret(type);
        }

        /// <summary>
        /// [OPTIONAL] You may specify the URL that is used for the OIDC authority, but typically, you will
        /// specify TENANT_ID and this URL will be built for you. If you are going to use this for multi-tenant
        /// authentication, then you must set AUTHORITY to "https://login.microsoftonline.com/common".
        /// </summary>
        public static string AzureAuthority
        {
            get => GetOnce("AZURE_AUTHORITY", "AUTHORITY").AsString(() =>
            {
                if (!string.IsNullOrEmpty(AzureTenantId)) return $"https://login.microsoftonline.com/{AzureTenantId}";
                return null;
            });
        }

        /// <summary>
        /// [OPTIONAL] This allows you to specify the Client ID for a Google login.
        /// </summary>
        public static string GoogleClientId
        {
            get => GetOnce("GOOGLE_CLIENT_ID");
        }

        /// <summary>
        /// [OPTIONAL] You may specify the URL that is used for the /cas/token endpoint that will built the JWT.
        /// Typically, you will set SERVER_HOST_URL and this URL will be built for you.
        /// </summary>
        public static string RedirectUri(HttpRequest request = null)
        {
            string s = GetOnce("REDIRECT_URI");

            // apply variables
            if (string.Compare(s, "$RequestDomain", StringComparison.InvariantCultureIgnoreCase) == 0 && request != null)
            {
                string protocol = IsHttps ? "https" : "http";
                string port = request.Host.Port != null ? ":" + request.Host.Port : "";
                s = $"{protocol}://{request.Host.Host}{port}/cas/token";
            }

            // derive from SERVER_HOST_URL
            if (string.IsNullOrEmpty(s) && !string.IsNullOrEmpty(ServerHostUrl))
            {
                s = new Uri(ServerHostUrl).Append("/cas/token").AbsoluteUri;
            }

            return s;
        }

        /// <summary>
        /// [OPTIONAL] You may specify the URL that the user will be redirected to after authentication.
        /// If you do not specify this, it will default to WEB_HOST_URL and then CLIENT_HOST_URL. This
        //  is not required because the /authorize request can specify a callback.
        /// </summary>
        public static string DefaultRedirectUrl
        {
            get => GetOnce("DEFAULT_REDIRECT_URL").AsString(() => WebHostUrl ?? ClientHostUrl);
        }

        /// <summary>
        /// [OPTIONAL] If you want to query the Microsoft Graph when a JWT is issued that will show roles for
        /// multiple applications, you should set this to a comma-delimited list of application GUIDs.
        /// </summary>
        public static string[] AzureApplicationIds
        {
            get => GetOnce("AZURE_APPLICATION_ID", "APPLICATION_ID").AsArray(() => null);
        }

        /// <summary>
        /// [OPTIONAL] If you want to provide a hint for the domain so that users can authenticate easier,
        /// you can specify that. Generally it is best to leave it unset.
        /// </summary>
        public static string AzureDomainHint
        {
            get => GetOnce("AZURE_DOMAIN_HINT", "DOMAIN_HINT");
        }

        /// <summary>
        /// [OPTIONAL] If you want to provide a hint for the domain so that users can authenticate easier,
        /// you can specify that. Generally it is best to leave it unset.
        /// </summary>
        public static string GoogleDomainHint
        {
            get => GetOnce("GOOGLE_DOMAIN_HINT");
        }

        /// <summary>
        /// [OPTIONAL, default: 4 hours] You may specify a number of minutes for the JWT expiry when generated
        /// for user authentication.
        /// </summary>
        public static int JwtDuration
        {
            get => GetOnce("JWT_DURATION").AsInt(() => 60 * 4); // 4 hours
        }

        /// <summary>
        /// [OPTIONAL] You may specify a number of minutes for the JWT expiry when generated
        /// for service authentication. If this is not specified, the duration is the same as JWT_DURATION.
        /// </summary>
        public static int JwtServiceDuration
        {
            get => GetOnce("JWT_SERVICE_DURATION").AsInt(() => JwtDuration);
        }

        /// <summary>
        /// [OPTIONAL, default: 7 days] This setting determines the maximum duration from the initial
        /// issuing of the JWT. If this duration is exceeded the reissue process will not issue a replacement
        /// token. If you set this to "0" there will not be a maximum duration.
        /// </summary>
        public static int JwtMaxDuration
        {
            get => GetOnce("JWT_MAX_DURATION").AsInt(() => 60 * 24 * 7); // 7 days
        }

        /// <summary>
        /// [OPTIONAL, default: true] When this is set to true, the Microsoft Graph will be queried to ensure
        /// the user is still enabled before reissuing a token.
        /// </summary>
        public static bool RequireUserEnabledOnReissue
        {
            get => GetOnce("REQUIRE_USER_ENABLED_ON_REISSUE").AsBool(() => true);
        }

        public static bool GoogleEmailMustBeVerified
        {
            get => GetOnce("GOOGLE_EMAIL_MUST_BE_VERIFIED").AsBool(() => true);
        }

        /// <summary>
        /// [OPTIONAL, default: secret] When issuing administrative commands against the server the command password ensures
        /// the user is authorize to make the change. It is done this way instead of using ROLE_FOR_ADMIN
        /// in case the authentication is not working.
        /// </summary>
        public async Task<string> CommandPassword()
        {
            return await GetSecret<string>("COMMAND_PASSWORD", str =>
            {
                if (string.IsNullOrEmpty(str) && UseInsecureDefaults) return "secret";
                return str;
            });
        }

        /// <summary>
        /// [OPTIONAL] The server requires a private key to sign the JWT. This can be obtained by setting
        /// PRIVATE_KEY or USE_INSECURE_DEFAULTS (localhost debugging only).
        /// </summary>
        public async Task<string> PrivateKey()
        {
            return await GetSecret<string>("PRIVATE_KEY", str =>
            {
                if (string.IsNullOrEmpty(str) && UseInsecureDefaults) return
                    @"MIIPWQIBAzCCDx8GCSqGSIb3DQEHAaCCDxAEgg8MMIIPCDCCBT8GCSqGSIb3DQEH
                    BqCCBTAwggUsAgEAMIIFJQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQI66P6
                    bfpDrKICAggAgIIE+KL7yE+LJQJZ4SrXcRrbIkZGfWahdLFb/3Vqp2zUkJjPYnMA
                    SCg5Jqb/a/jnAac21/72J8pdfY5nTcc7KAsHQ2lXJmIXTTeF/3LVt8VHobIaGrey
                    KZ0oFhji2TJwYQmmG4s8kclmJFPw6d7uSr8+kONH7l3lfn4guXXqMx/NIJ4G669e
                    q3yxHua1KlZHh0TiWY4RFPa0rC1JHQ3LyqJIypdEMLQcUFddvN+PhmM2clDCkxhn
                    KNTTnqx1et4Nj+zwOXbDaC9LsQ1FdKypgP/WmbFuGxGbzry8/9ujQZI8oyPyfBt3
                    gUXwTua/fSkEcj/VMdzjBYygWt9LN8rkrduGpz9BmUvkj58671l7AIX8FtetaJSW
                    /PvuEKOPLo2DqB0DZbwNBl370EsjOfMT4ixIyqssX4nfiELhCrnTc6iQI7AWR28D
                    kuhVVKAGrxcSFFAinQ6c1nave5d6+haP4q8mz52wkrDbbIsBKI6jmrBODDjWXSyI
                    xv7bjpI/akzWyl9IBvnWsVDg8Lvz9kxFYVX6Z5gwKqvpgZj8RKJOofu8W+r+UKQW
                    r3fudy7PB7UtC07nId3Li65Zyg8MpMr51XiWqgjVP3GWaQ6s+zjWtV8Xcop3td3I
                    CqgvbIe7dZOw3L+WQwjXMhPY4ps7My8GATVPl2z6FEIvse3iciVPpa6uq60bczDc
                    D+noCEaU2xJFDp9mARNLjOlxnZ7IErBEU0mQkQ/UN0jaA3b+cDtxtIew82E4xek0
                    FYIfoIXDqZuFcj/ebuqiWcGUOIoA9tXsjllYH1qh2Oqrs8kt1XtXoaSDl7kI/x9R
                    P91Yqw1tK2q5d8wDg4eRBQeEAg/64Op+l6uDad1vgokdSftDyJb43dEpqB5tf82H
                    uHDAAvynznoseoeZBEchLOdHpi/jiPUfBdfNsmq0SCQt3YenWzOHBpzLJI9kKd2V
                    7rrG5jObDpCafufWRuHL+B79v5a2iwciRS77txAPhKzJb//feYgSDxzZH63upeyY
                    mbuuosST9+GT4qKyoXH3hJchULabCgaJBqdE8zRgnuKCeBi/0lWxRprdShADdnD5
                    jaULSbNiZjgMjCeQP3fKYEpOh00wtouV4cdNk2MyKdDivsw1oL8RhrdJv3MeTncx
                    /9aV0seNhLPY50oID39sIyyQN5H8saglwH8qWlqAUFigm0ahXXZBx5AX051t15gd
                    jib1nmp/L3VrnV3EsDlM54HYo3Yjf25/7NommRatMvkWmyvqS2EgfvjGq3bjPvp+
                    VdQwBQ/i7JzSzL5JAT56PWDJyjKOyEW9UDxGYG4zQ2bSVcfhP7W0kIFgVhBvw4aq
                    Iz5rsJerUOQHopqmnikxglFSoOhCCD2fN55ZxA1jRHc6A+qMceJHnsQ2nlc4GSOv
                    bXh0OP6f/MKrEE48LQFLUKpCfp5uZwZcx3VUetFv/6JvRzE04hsOy9O9p8WrFE8Q
                    ZSUZ0aoP9lyAuXBW/lAkNLetWEGy1BU8FmOmx6Z4pCTqtJWPLmWEnwsCpbkLNiOq
                    6sCYzpDhEGZO+CnLbJo7CapXI6uzLWXHg/rgOPhh2FaVyIn+PkH+mLCH+C6MPtD1
                    BS9tr4C36Ys/HVj/JdRvTc69gZjfF0H5UNjxHfGNZCbA3TOhsUdFHO5JJbK1Krq9
                    Vm54RhK24ZOg95qc/LvLHnvPRVOb+K/DoCVMf9qKCZIXBPUGUDCCCcEGCSqGSIb3
                    DQEHAaCCCbIEggmuMIIJqjCCCaYGCyqGSIb3DQEMCgECoIIJbjCCCWowHAYKKoZI
                    hvcNAQwBAzAOBAjfD2wM3nAA+gICCAAEgglINm8K49ztNxW+UO0TONMUOlpy9/hd
                    tvpSuzyRIUhSdGA8nHd4hy8pyDkjyaH5o2Fss/2qnz0ILk2r3G5ELFd2IPXeJkjD
                    ssG2gzuPxDACf5+zNX81hkrYB0jsoMvFC7nreiSeSxHoPrsCk1ULrdRSiC2uK+WV
                    eKqDj7NJ/+XpzdY8bmEjpa+Apivl31bD+94dpZMeSSZAR/WyUdzpwgqeK5s6SCVK
                    Hl4GLBOexf3j2uOpq0Bktbs2pvDGdMzgzBiOKBMFV5PR+BWYDHB8Y1NUTzX1V/Zw
                    0igVcYFRv9h26VUWiNWqwU3vU7Ts/wWXhylel5lO1NNzMnQQZt3zNvTpgWVa0A9x
                    C7v/EqxIl3saiynn3BEaFYMneRmJX46KuzZVt/HtwoQ0dM6I2BwswY0+BrBs0Ow4
                    svODyhAD3g/VP9l0hVyV8ra4j9lgZ7DHabcWk2OEnpmvQ4fMA9uotZAt4ULwz31V
                    mt6/HpuFCYgPoDl0Wx8kKJmFvgphbsuUGPhm8mm2D1L1XkveOeQesdSBNxZeHtxf
                    itGC2DPTM/MnC78t1l84I6MD0YgQpGOLbs49gJoT3yJkJH3NUQkmFSosWFdFaYKf
                    YNToTqUj6WMtoB1nTonKVY+l9MEoOZgXBam8gdo8ZjxlLFTUF40uUWtzIg6Mvttk
                    FNMaJSnetO141cWfaPswZtF+b3Wj2KnO/i3U4VCBbHUuXSfpl2neFqlmWRtpsQCS
                    uAyQptRQR8hff/Z3UK6aDOKiyUEye7Cu/MAP7hH5apgYAv0E9bjkhcBAqwXayAfl
                    IAFHTN85j5VZmLRzmAxGwFIoreuiVIqmmSeRRRYrrSVBtkjfs+cJfc7ajh3l6S+l
                    ZbOkf/qY4q0CK+AhGFJ+lkHLwPOoHNRufo67C9tN8wTlT9OPC++B8uq0Y7Za1d6Q
                    Hx9/Aax13fq/xZooW2VU0KfsHTqBe9RpdUg2rXQsN2HbFgWibI+wvpf4HSnz/DPG
                    ouqdvPLpW4HISdI9i2nd78yyS7Nbdm/NOsHiFQSO6hODuJ7/kQHlPxtxAWC4wYgW
                    //mii7bpBAKncjtGW4AsZJUYd/NDJmw0a1iM4fl+hXDo6Zfbno3hM2Q+2ayyzucZ
                    y8iGy7f3OuYXKu3CwmYxLQaxNCqlfxiXC4hsBOwJ6p7H+rUD0Aq7HIXFTDp33vFi
                    5a61Wql4CYLKiVcQsZCL1/4WZd73IrHDMsg79EFebYrxPn3YLt4OYesENje/bX5c
                    c3bDPzHvL9T+ZuYAj7gfCIg3lbin51wRpcPLT+I3rM3k0XVaN7sQj0oI8NCGQjm2
                    R+Vgm5m/YrWSXnlZp/cWIekZz3ynuhIScnxXB/DpWuay70r0WK7+1wSA/Vcq1trS
                    ktw25dUYjWR+7NtosHWYffhmZlc+AHpBmeylVkomL51pe8L61qItr9e6crwnz5Os
                    Z7Jq+maRKJtYsyGLMY0zz5L6uPP00jAbMc2AdvddwRHXPeyVi7qoRun133FzZLvv
                    bRuGXcF3GleR5F5pSKAJ9gfONr2r7hKOl1G+sEklTOXw/Bid/6v1UHvV4h/7dS5z
                    LPoi8PnssYNjD7Zup6Xt0Afa9Cd2AConcflMdGyK9knhKL3FzQHXKtxxzh6qJiiO
                    T0d50TddcUxaoqjgFLdbM1U9EV9WLewB2gKkCi6CISfIgdcm+16aVuqij3XqaZum
                    JJVA/IvWXOfNnVQfnHq+iEmvN85ydQTk3GLM6t5kq87LTxC2enElh3ZQOT+UAnuU
                    MWd4+325AO9UYDX1iPHCFmqMbdZ3dP+1rwDBbg3uF4UUlgFeSnan/yMqXC8r1tH4
                    +7exGiALC+CkjCQT8RURlDvXWup5EaWohnTXsWdRCs69lPf4Ls4JcpTvg/U0SM9Q
                    BSAne0sf7jF8klVUprw17Mb4+gfcC36KA38Tb8PSWvibkkzNqSIikhujCqKiZPBx
                    3izA4V3Fd4ajnP2AGBMIv+LRlt+EDmuRULOJzJp/2i1af89jjFqyxYzOiizzjwFt
                    QIiKTvjDQiwOUyiZY5ZBVwW9WFKPZmf5VcolXtvHtLIbC2NAxjn3UV4ygsQRKfgb
                    w8GkGZB9cSas57tvrX6lVitWIkjGD9qgUSxMU3DPwxO/hR8hx7P68U0RqqyGN8Le
                    01rj8DbJ9ujIO6PYUmL1qYtYKHL+8LuszDRiaddEEBzMV1MHCf3JyO3ECcsJlf+T
                    qgwbC6//v8GrE5TdDC7PPR+Fz2CpR4vWbjTK9zQMiUr/Q1gA3a8nSyRXl7cElhaL
                    upQ3Y5kky6kOtL/KJviF++NxyKGVR73fd7OzThHNEfGB3k0pgHEUpdv/c8ehnSer
                    SNJfqKJfhf+skXKLraHlnGCQoKMCpYxUrfQgS4C87OSq4jwggGr5JZPwhobw6wKs
                    LAQ/RLj34i/2ANxHenbTdLTM75ovRNTeiR74aX09spFQMVEKhcjGGvVA25k5cCNl
                    T5lMOQozLa0838/9C0t0elvCvaNMAe3LUifpkYUrbNeQezM5F2Xq5H32WrBn6e3v
                    vHO+IVkhPITMaWMmnC6ZIrYJg5EsbKCZRWWEjdpoCkGS1Kj1botwsfKB+ITiCRAN
                    FJkIrRQl/0UEXXZTn8DgSqtf3+Y2f6SfPxYcfCeWpp1mS8VpImuWnQIivM8Sac0E
                    nUNsF0WFoQQXnAnRl3jWW27dT6cC1mkzpxpyNk/k0lv8YsoOcoT96dpaZhFNg6Nu
                    Zm9V4tMXwDTeZ9/6JLxjpvjW3P0BM0ZJAEp5NaAXMmsIjXF1R/USozrrML7eu7OS
                    yYeBcktrd9fXa9NyJvWT+jH4m7EfBaZsdXq5LhYGpE1fZDUey71XYMEJBsC+EI1k
                    W8LmFu3aIaBO6jk3LMCnHA/Rcv0Q215sXRxT+1E4W43RaXWnNYtXcPOtEk4FBb5x
                    bwWtmYiJwcdaicJ72jpdRXCdzXlb/QUt4lGtCIi0U1A4UHrlg2sXoXSe76XKQUpR
                    tMMvYKrwnXwiqwI3+UBJs8PI+BtAJpOhml1V9x7I6tdMETx9kXEIbO8/wuMaz+UN
                    QlDZov+8/6VBxjOdZzQJjTXUlr/duAposFakz4YuhKp5w73nwRPocG/AL5Yck8Ee
                    io/0SRRG33g+OH+3CPirVDYm9BZ6J3hRcpKXinCcbohZUzC6XFgsOofXWs+caaEB
                    7LULMSUwIwYJKoZIhvcNAQkVMRYEFCmOnNCgq5wbNyXJ9PF1IwY7yA6gMDEwITAJ
                    BgUrDgMCGgUABBSCCb4i0bVxO1wFo7w/FB+2IPpFRgQIh+R+IQq1RO4CAggA";
                return str;
            });
        }

        /// <summary>
        /// [OPTIONAL] The server requires that the private key be secured by a password. This can be obtained by setting
        /// PRIVATE_KEY_PASSWORD or USE_INSECURE_DEFAULTS (localhost debugging only).
        /// </summary>
        public async Task<string> PrivateKeyPassword()
        {
            return await GetSecret<string>("PRIVATE_KEY_PASSWORD", str =>
            {
                if (string.IsNullOrEmpty(str) && UseInsecureDefaults) return "secret";
                return str;
            });
        }

        /// <summary>
        /// [OPTIONAL] The server requires public certificates that can be used to verify that this server issued
        /// the JWT. This can be obtained by setting PUBLIC_CERT_0, PUBLIC_CERT_1, PUBLIC_CERT_2, PUBLIC_CERT_3,
        /// or USE_INSECURE_DEFAULTS (localhost debugging only).
        /// </summary>
        public async Task<string> PublicCert(int index)
        {
            return await GetSecret<string>($"PUBLIC_CERT_{index}", str =>
            {
                if (index == 0 && string.IsNullOrEmpty(str) && UseInsecureDefaults) return
                    @"-----BEGIN CERTIFICATE-----
                    MIIEljCCAn4CCQD50gnTNYT+YTANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
                    UzAeFw0yMDAyMDEwMDQxMTFaFw0zMDAxMjkwMDQxMTFaMA0xCzAJBgNVBAYTAlVT
                    MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtt3sn0kjsr6D+ZBOD/N4
                    9GBY53gNwa7STqmA+RGwp09//ulAqcu3oDVQVw/cVdbU1YMmvLsRsFxBERBmUN6q
                    x9HNX4LF8pNZTEFhnMaJOuToaHV86tCmJbC0H1lBPkV7QBuyTh30VO17zbT6jvnI
                    kheoo5N7vKQriimb7h8O+1cgKlP6SJ4tsH9IyguduM9k82POAZmde+R8OCovpttE
                    +E68maM71CXVHxrBONX5ZZ+c5MxPkDHquBhhhWAPYsocdFWV6LrOy3SGI6ksPmlV
                    WOYWMSvQ0ihXXk2lFeG+9+WuBn3yVLRXMJGUOSNGAPn8Rb/UhHUokS90A5UcCO3Q
                    ELXuV3dVozY1czOwNXn/Fw3TJxJYarkC+uRNiHNc8dIkUQTg6Khu/kel6vF5bwPZ
                    zOwwvBDWMf8q9OZhsXM0bQ3xz2KMO2+LZQ1m5nhn6QKls4AgHkuewUWVbnR3N4GQ
                    aqrYeevf+qBWm1XtIiHKGGA6GcWc9npG3ZtSDHXckWE0zT5RbIgBhaZBGkKCknYa
                    EI8AM/t9r3nAJCx8SfZIwhvnHmXwEPHHWGkLVEkn5vGEC/U5GEjFy5T8mJwQwrQ1
                    yuvGLP1XvwLfz/GzhMMVDofrCzIwcl9u9HcmaS4gpdaIpZJHhYtEJZ+MFTTxqQVz
                    SfxIQqbb4+oXPqBFvR9YRFcCAwEAATANBgkqhkiG9w0BAQsFAAOCAgEApDXK6Uts
                    LFMMEWyw1rTZcLVCAO+Y309n3QWtiNtc1wZ8Gug9m7nvcdUdWo5MkuviudegkLrU
                    PIzUZMmgVYytcpgVgQ6v5onTgXl8/8xEkWwNZMC4oWr9gnQx8TlSqj9MRWByciyY
                    j/GTtfyjkS2Wom4I6Qp9tBnREt+7lonjKhVO2byuIbs0fVNOKkvG+I4tjez4QwTL
                    YYSkDrPacfp+MVay7yovUzZPq/Nnlyt8Rz3Vk3evSJX43ALfgMDxCwA91Zsc9sap
                    7ZhbNFebIyaBe+OtIFvd9ruzu0+cnUcV1m2NZIChUF31E/gpCW4z0TpElboaD/Q6
                    hsWV0GjSKG9apvxW+udkzICHHKSbPGPnemLNsp/CG0nJCptaAfZ2oblsLzlA9MCc
                    bsXrIwn7DPh7nOJrJ7f1jeeOlvxRAuPSY/a33EkcmkVmZUrbAh5C5WDKTO0cl21T
                    PigaqiVXI376VF2cuJ6s/YM7Zc7HkKl+qgHd2s2Q2hcwj6J9Nr3zCJL2zW2RsKZ+
                    BWgJChVKYLzCrdkIdDq/HDjYqUn7kW6p/R61uJ2r0HhV3j3bUy4Z79+KWVOykmCg
                    azVj1MubtEdScZvrJrv8wwZ4JiE0QaKD5f6QmJtJQi/I2xzZ4KHVNzNUGxjlAQeG
                    rZvYuY1wwqr2AHQjRrLwwT4N3ms7dPVeSHg=
                    -----END CERTIFICATE-----";
                return str;
            }, ignore404: true);
        }










    }

}