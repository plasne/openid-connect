using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Specialized;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http;

namespace CasAuth
{

    public class CasServerAuthMiddleware
    {
        // used just for ILogger
    }

    public static class UseCasServerAuthMiddlewareExtensions
    {

        private class HttpException : Exception
        {

            public HttpException(int code, string msg) : base(msg)
            {
                this.StatusCode = code;
            }

            public int StatusCode { get; set; }
        }

        private static string GenerateSafeRandomString(int length)
        {
            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
            var bytes = new byte[length];
            provider.GetBytes(bytes);
            string s = Convert.ToBase64String(bytes);
            s = s.Split('=')[0];
            s = s.Replace('+', '-');
            s = s.Replace('/', '_');
            return s;
        }

        private class AuthFlow
        {
            public string redirecturi { get; set; }
            public string state { get; set; }
            public string nonce { get; set; }
        }

        private static async Task<JwtSecurityToken> VerifyTokenFromAAD(CasTokenIssuer tokenIssuer, string token, string audience = null, string nonce = null)
        {
            var handler = new JwtSecurityTokenHandler();

            // get configuration info from OpenID Connect endpoint
            //  note: this is cached for 1 hour by default
            OpenIdConnectConfiguration config = await tokenIssuer.ConfigManager.GetConfigurationAsync();

            // determine the possible appropriate issuers
            var issuers = new List<string>();
            string tenant = CasEnv.Authority.Split("/").LastOrDefault();
            if (tenant == "common")
            {
                // multi-tenant; the issuer will be the directory containing the user
                var unvalidatedJwt = handler.ReadJwtToken(token);
                var tid = unvalidatedJwt.Payload.Claims.FirstOrDefault(c => c.Type == "tid");
                if (tid != null) issuers.Add($"https://login.microsoftonline.com/{tid.Value}/v2.0");
            }
            else
            {
                // single-tenant; users are issued from the first, but applications respond with the second
                issuers.Add($"https://login.microsoftonline.com/{tenant}/v2.0");
                issuers.Add($"https://sts.windows.net/{tenant}/");
            }

            // define the validation parameters
            var validationParameters = new TokenValidationParameters
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuers = issuers.ToArray(),
                ValidateAudience = (!string.IsNullOrEmpty(audience)),
                ValidAudience = audience,
                ValidateLifetime = true,
                IssuerSigningKeys = config.SigningKeys
            };

            // validate all previously defined parameters
            SecurityToken validatedSecurityToken = null;
            handler.ValidateToken(token, validationParameters, out validatedSecurityToken);
            JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;

            // validate alg
            if (validatedJwt.Header.Alg != SecurityAlgorithms.RsaSha256) throw new SecurityTokenValidationException("The alg must be RS256.");

            // validate nonce
            if (string.IsNullOrEmpty(nonce))
            {
                // nonce not provided
            }
            else if (validatedJwt.Payload.Nonce != nonce)
            {
                throw new SecurityTokenValidationException("The nonce was invalid.");
            }

            return validatedJwt;
        }

        public class Tokens
        {
            public string access_token { get; set; }
            public string refresh_token { get; set; }
        }

        public static async Task<Tokens> GetAccessTokenFromAuthCode(HttpClient httpClient, CasTokenIssuer tokenIssuer, string code, string scope)
        {

            // get the client secret
            var secret = await tokenIssuer.GetClientSecret();

            // get the response
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"{CasEnv.Authority}/oauth2/v2.0/token"),
                Method = HttpMethod.Post
            })
            {
                using (request.Content = new FormUrlEncodedContent(new[] {
                    new KeyValuePair<string, string>("client_id", CasEnv.ClientId),
                    new KeyValuePair<string, string>("client_secret", secret),
                    new KeyValuePair<string, string>("scope", scope),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", CasEnv.RedirectUri),
                    new KeyValuePair<string, string>("grant_type", "authorization_code")
                }))
                {
                    using (var response = await httpClient.SendAsync(request))
                    {
                        var raw = await response.Content.ReadAsStringAsync();
                        if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"CasServerMiddleware.GetAccessTokenFromAuthCode: HTTP {(int)response.StatusCode} - {raw}");
                        }
                        var tokens = JsonSerializer.Deserialize<Tokens>(raw);
                        return tokens;
                    }
                }
            };

        }

        public static async Task<Tokens> GetAccessTokenFromRefreshToken(HttpClient httpClient, CasTokenIssuer tokenIssuer, string refreshToken, string scope)
        {

            // get the client secret
            var secret = await tokenIssuer.GetClientSecret();

            // get the response
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"{CasEnv.Authority}/oauth2/v2.0/token"),
                Method = HttpMethod.Post
            })
            {
                using (request.Content = new FormUrlEncodedContent(new[] {
                    new KeyValuePair<string, string>("client_id", CasEnv.ClientId),
                    new KeyValuePair<string, string>("client_secret", secret),
                    new KeyValuePair<string, string>("scope", scope),
                    new KeyValuePair<string, string>("refresh_token", refreshToken),
                    new KeyValuePair<string, string>("grant_type", "refresh_token")
                }))
                {
                    using (var response = await httpClient.SendAsync(request))
                    {
                        var raw = await response.Content.ReadAsStringAsync();
                        if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"CasServerMiddleware.GetAccessTokenFromRefreshToken: HTTP {(int)response.StatusCode} - {raw}");
                        }
                        var tokens = JsonSerializer.Deserialize<Tokens>(raw);
                        return tokens;
                    }
                }
            };

        }

        private static async Task<Tokens> GetAccessTokenFromClientSecret(HttpClient httpClient, string clientId, string clientSecret, string scope)
        {

            // get the response
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"{CasEnv.Authority}/oauth2/v2.0/token"),
                Method = HttpMethod.Post
            })
            {
                using (request.Content = new FormUrlEncodedContent(new[] {
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("client_secret", clientSecret),
                    new KeyValuePair<string, string>("scope", scope),
                    new KeyValuePair<string, string>("grant_type", "client_credentials")
                }))
                {
                    using (var response = await httpClient.SendAsync(request))
                    {
                        var raw = await response.Content.ReadAsStringAsync();
                        if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"CasServerMiddleware.GetAccessTokenFromClientSecret: HTTP {(int)response.StatusCode} - {raw}");
                        }
                        var tokens = JsonSerializer.Deserialize<Tokens>(raw);
                        return tokens;
                    }
                }
            };

        }

        private static async Task<Tokens> GetAccessTokenFromClientCertificate(HttpClient httpClient, string clientId, string token, string scope)
        {

            // get the response
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"{CasEnv.Authority}/oauth2/v2.0/token"),
                Method = HttpMethod.Post
            })
            {
                using (request.Content = new FormUrlEncodedContent(new[] {
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    new KeyValuePair<string, string>("client_assertion", token),
                    new KeyValuePair<string, string>("scope", scope),
                    new KeyValuePair<string, string>("grant_type", "client_credentials")
                }))
                {
                    using (var response = await httpClient.SendAsync(request))
                    {
                        var raw = await response.Content.ReadAsStringAsync();
                        if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"CasServerMiddleware.GetAccessTokenFromClientSecret: HTTP {(int)response.StatusCode} - {raw}");
                        }
                        var tokens = JsonSerializer.Deserialize<Tokens>(raw);
                        return tokens;
                    }
                }
            };

        }

        public class WellKnownConfigPayload
        {
            public string issuer { get; set; }
            public string jwks_uri { get; set; }
        }

        public class Key
        {
            public string kty { get { return "RSA"; } }
            public string use { get { return "sig"; } }
            public string kid { get; set; }
            public string x5t { get; set; }
            public string n { get; set; }
            public string e { get; set; }
            public List<string> x5c { get; set; } = new List<string>();

            public Key(X509Certificate2 certificate)
            {

                // get the parameters of the public key
                var pubkey = certificate.PublicKey.Key as dynamic;
                var parameters = pubkey.ExportParameters(false);

                // populate the info
                kid = certificate.Thumbprint;
                x5t = Convert.ToBase64String(certificate.GetCertHash()).Replace("=", "");
                n = Convert.ToBase64String(parameters.Modulus).Replace("=", "");
                e = Convert.ToBase64String(parameters.Exponent);
                x5c.Add(Convert.ToBase64String(certificate.RawData));

            }
        }

        public class KeysPayload
        {
            public List<Key> keys { get; set; } = new List<Key>();
        }

        public class CasServerAuthOptions
        {
            public IEnumerable<string> AdditionalScopes { get; set; }
            public Action<Func<string, Task<Tokens>>> AuthCodeFunc { get; set; }
        }

        public static IApplicationBuilder UseCasServerAuth(this IApplicationBuilder builder, CasServerAuthOptions opt = null)
        {

            // define additional endpoints
            builder.UseEndpoints(endpoints =>
            {

                // define the authorize endpoint
                endpoints.MapGet("/cas/authorize", context =>
                {
                    try
                    {

                        // get the necessary variables
                        string redirecturi = context.Request.Query["redirecturi"];
                        string authority = CasEnv.Authority;
                        string clientId = WebUtility.UrlEncode(CasEnv.ClientId);
                        string redirectUri = WebUtility.UrlEncode(CasEnv.RedirectUri);
                        // REF: https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
                        string scope = (opt.AdditionalScopes != null && opt.AdditionalScopes.Count() > 0) ?
                            WebUtility.UrlEncode("openid profile email " + string.Join(" ", opt.AdditionalScopes)) :
                            WebUtility.UrlEncode("openid profile email");
                        string response_type = (opt.AuthCodeFunc != null) ?
                            WebUtility.UrlEncode("id_token code") :
                            WebUtility.UrlEncode("id_token");
                        string domainHint = WebUtility.UrlEncode(CasEnv.DomainHint);

                        // generate state and nonce
                        AuthFlow flow = new AuthFlow()
                        {
                            redirecturi = (string.IsNullOrEmpty(redirecturi)) ? CasEnv.DefaultRedirectUrl : redirecturi,
                            state = GenerateSafeRandomString(16),
                            nonce = GenerateSafeRandomString(16)
                        };

                        // store the authflow for validating state and nonce later
                        //  note: this has to be SameSite=none because it is being POSTed from login.microsoftonline.com
                        context.Response.Cookies.Append("authflow", JsonSerializer.Serialize(flow), new CookieOptions()
                        {
                            Expires = DateTimeOffset.Now.AddMinutes(10),
                            HttpOnly = true,
                            Secure = CasEnv.RequireSecureForCookies,
                            SameSite = SameSiteMode.None
                        });

                        // redirect to url
                        string url = $"{authority}/oauth2/v2.0/authorize?response_type={response_type}&client_id={clientId}&redirect_uri={redirectUri}&scope={scope}&response_mode=form_post&state={flow.state}&nonce={flow.nonce}";
                        if (!string.IsNullOrEmpty(domainHint)) url += $"&domain_hint={domainHint}";
                        context.Response.Redirect(url);
                        return context.Response.CompleteAsync();

                    }
                    catch (HttpException e)
                    {
                        context.Response.StatusCode = e.StatusCode;
                        return context.Response.WriteAsync(e.Message);
                    }
                    catch (Exception e)
                    {
                        context.Response.StatusCode = 500;
                        var logger = context.RequestServices.GetService<ILogger<CasServerAuthMiddleware>>();
                        logger.LogError(e, "Exception in /cas/authorize");
                        return context.Response.WriteAsync("internal server error");
                    }
                });

                // define the token endpoint
                endpoints.MapPost("/cas/token", async context =>
                {
                    try
                    {
                        var tokenIssuer = context.RequestServices.GetService<CasTokenIssuer>();
                        var httpClientFactory = context.RequestServices.GetService<IHttpClientFactory>();
                        var httpClient = httpClientFactory.CreateClient("cas");

                        // read flow, verify state and nonce
                        if (!context.Request.Cookies.ContainsKey("authflow")) throw new HttpException(400, "authflow not provided");
                        AuthFlow flow = JsonSerializer.Deserialize<AuthFlow>(context.Request.Cookies["authflow"]);
                        if (context.Request.Form["state"] != flow.state) throw new HttpException(400, "state does not match");

                        // throw error if one was returned
                        if (context.Request.Form.ContainsKey("error_description"))
                        {
                            throw new Exception(context.Request.Form["error_description"]);
                        }

                        // verify the id token
                        string idRaw = context.Request.Form["id_token"];
                        var idToken = await VerifyTokenFromAAD(tokenIssuer, idRaw, CasEnv.ClientId, flow.nonce);

                        // AuthCode: use the code to get an access token
                        if (opt.AuthCodeFunc != null)
                        {
                            string code = context.Request.Form["code"];
                            Tokens last = null;
                            Func<string, Task<Tokens>> getAccessToken = async (scope) =>
                            {
                                if (last == null)
                                {
                                    last = await GetAccessTokenFromAuthCode(httpClient, tokenIssuer, code, scope);
                                }
                                else
                                {
                                    last = await GetAccessTokenFromRefreshToken(httpClient, tokenIssuer, last.refresh_token, scope);
                                }
                                return last;
                            };
                            opt.AuthCodeFunc(getAccessToken);
                        }

                        // populate the claims from the id_token
                        List<Claim> claims = new List<Claim>();
                        var email = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "email");
                        if (email != null) claims.Add(new Claim("email", email.Value));
                        var displayName = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "name");
                        if (displayName != null) claims.Add(new Claim("displayName", displayName.Value));

                        // add the user account type
                        claims.Add(new Claim("typ", "user"));

                        // get the oid
                        if (CasEnv.Authority.EndsWith("/common"))
                        {

                            // add the tenant claim
                            var tid = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "tid");
                            if (tid != null) claims.Add(new Claim("tenant", tid.Value));

                            // oids for external users are wrong, we need to query for them
                            var oid = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "oid");
                            if (oid != null)
                            {
                                if (await CasTokenIssuer.GetUserById(httpClient, oid.Value) == null)
                                {
                                    // query by userPrincipalName
                                    var username = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "preferred_username");
                                    if (username != null)
                                    {
                                        string userId = username.Value.Replace("@", "_");
                                        var users = await CasTokenIssuer.GetUserById(httpClient, $"?$filter=startsWith(userPrincipalName, '{userId}%23EXT%23')");
                                        if (users != null && users.value.Count > 0)
                                        {
                                            claims.Add(new Claim("oid", (string)users.value[0].id));
                                        }
                                    }
                                }
                                else
                                {
                                    // the oid was valid; the user is local
                                    claims.Add(new Claim("oid", oid.Value));
                                }
                            }

                        }
                        else
                        {
                            // oids for 1st party users are fine
                            var oid = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "oid");
                            if (oid != null) claims.Add(new Claim("oid", oid.Value));
                        }

                        // attempt to propogate roles
                        var roles = idToken.Payload.Claims.Where(c => c.Type == "roles");
                        foreach (var role in roles)
                        {
                            claims.Add(new Claim("roles", role.Value));
                        }

                        // Service-to-Service: get other claims from the graph (req. Directory.Read.All)
                        //    or from a database
                        /*
                        dynamic user = await tokenIssuer.GetUserById(oid.Value);
                        claims.Add(new Claim("displayName2", (string)user.displayName));
                        */

                        // write the XSRF-TOKEN cookie (if it will be verified)
                        if (CasEnv.VerifyXsrfInHeader || CasEnv.VerifyXsrfInCookie)
                        {
                            string xsrf = GenerateSafeRandomString(16);
                            string signed = xsrf;
                            if (!CasEnv.RequireHttpOnlyOnUserCookie)
                            {
                                // if the source claim is going to be in a cookie that is readable by JavaScript the XSRF must be signed
                                signed = await tokenIssuer.IssueXsrfToken(xsrf);
                            }
                            context.Response.Cookies.Append("XSRF-TOKEN", signed, new CookieOptions()
                            {
                                HttpOnly = CasEnv.RequireHttpOnlyOnXsrfCookie,
                                Secure = CasEnv.RequireSecureForCookies,
                                Domain = CasEnv.BaseDomain,
                                Path = "/"
                            });
                            claims.Add(new Claim("xsrf", xsrf));
                        }

                        // write the user cookie
                        string jwt = await tokenIssuer.IssueToken(claims);
                        context.Response.Cookies.Append("user", jwt, new CookieOptions()
                        {
                            HttpOnly = CasEnv.RequireHttpOnlyOnUserCookie,
                            Secure = CasEnv.RequireSecureForCookies,
                            Domain = CasEnv.BaseDomain,
                            Path = "/"
                        });

                        // revoke the authflow cookie
                        context.Response.Cookies.Delete("authflow");

                        // redirect to the appropriate place
                        context.Response.Redirect(flow.redirecturi);
                        await context.Response.CompleteAsync();

                    }
                    catch (HttpException e)
                    {
                        context.Response.StatusCode = e.StatusCode;
                        await context.Response.WriteAsync(e.Message);
                    }
                    catch (Exception e)
                    {
                        context.Response.StatusCode = 500;
                        var logger = context.RequestServices.GetService<ILogger<CasServerAuthMiddleware>>();
                        logger.LogError(e, "Exception in /cas/token");
                        await context.Response.WriteAsync("internal server error");
                    }
                });

                // define the endpoint for services authenticating with a certificate
                endpoints.MapPost("/cas/service", async context =>
                {
                    try
                    {

                        // get all needed variables
                        var tokenIssuer = context.RequestServices.GetService<CasTokenIssuer>();
                        var httpClientFactory = context.RequestServices.GetService<IHttpClientFactory>();
                        var httpClient = httpClientFactory.CreateClient("cas");
                        string clientId = context.Request.Form["clientId"];
                        string clientSecret = context.Request.Form["clientSecret"];
                        string token = context.Request.Form["token"];
                        string scope = context.Request.Form["scope"];

                        // get an access token and verify it
                        Tokens tokens = null;
                        if (!string.IsNullOrEmpty(token))
                        {
                            tokens = await GetAccessTokenFromClientCertificate(httpClient, clientId, token, scope + "/.default");
                        }
                        else if (!string.IsNullOrEmpty(clientSecret))
                        {
                            tokens = await GetAccessTokenFromClientSecret(httpClient, clientId, clientSecret, scope + "/.default");
                        }
                        else
                        {
                            throw new Exception("clientSecret or token must be supplied");
                        }
                        var accessToken = await VerifyTokenFromAAD(tokenIssuer, tokens.access_token, scope);

                        // populate the claims from the id_token
                        List<Claim> claims = new List<Claim>();
                        var oid = accessToken.Payload.Claims.FirstOrDefault(c => c.Type == "oid");
                        if (oid != null) claims.Add(new Claim("oid", oid.Value));

                        // add the service account type
                        claims.Add(new Claim("typ", "service"));

                        // attempt to propogate roles
                        var roles = accessToken.Payload.Claims.Where(c => c.Type == "roles");
                        foreach (var role in roles)
                        {
                            claims.Add(new Claim("roles", role.Value));
                        }

                        // return the newly issued token
                        string jwt = await tokenIssuer.IssueToken(claims);
                        await context.Response.WriteAsync(jwt);

                    }
                    catch (HttpException e)
                    {
                        context.Response.StatusCode = e.StatusCode;
                        await context.Response.WriteAsync(e.Message);
                    }
                    catch (Exception e)
                    {
                        context.Response.StatusCode = 500;
                        var logger = context.RequestServices.GetService<ILogger<CasServerAuthMiddleware>>();
                        logger.LogError(e, "Exception in /cas/service");
                        await context.Response.WriteAsync("internal server error");
                    }
                });

                // define the endpoint for reissuing tokens
                endpoints.MapPost("/cas/reissue", async context =>
                {
                    try
                    {

                        // get all needed variables
                        var tokenIssuer = context.RequestServices.GetService<CasTokenIssuer>();
                        string token = context.Request.Form["token"];

                        // ensure a token was passed
                        if (string.IsNullOrEmpty(token)) throw new HttpException(400, "token was not provided for renewal");

                        // see if it is eligible for reissue (an exception will be thrown if not)
                        var reissued = await tokenIssuer.ReissueToken(token);
                        await context.Response.WriteAsync(reissued);

                    }
                    catch (HttpException e)
                    {
                        context.Response.StatusCode = e.StatusCode;
                        await context.Response.WriteAsync(e.Message);
                    }
                    catch (Exception e)
                    {
                        context.Response.StatusCode = 500;
                        var logger = context.RequestServices.GetService<ILogger<CasServerAuthMiddleware>>();
                        logger.LogError(e, "Exception in /cas/reissue");
                        await context.Response.WriteAsync("internal server error");
                    }
                });

                // define the wellknownconfig endpoint
                endpoints.MapGet("/cas/.well-known/openid-configuration", context =>
                {
                    try
                    {

                        // compute the payload
                        // REF: https://ldapwiki.com/wiki/Openid-configuration 
                        // REF: https://developer.byu.edu/docs/consume-api/use-api/implement-openid-connect/openid-connect-discovery
                        var payload = new WellKnownConfigPayload()
                        {
                            issuer = CasEnv.Issuer,
                            jwks_uri = CasEnv.PublicKeysUrl
                        };

                        // return the json
                        string json = JsonSerializer.Serialize(payload);
                        context.Response.Headers.Add("Content-Type", "application/json; charset=utf-8");
                        return context.Response.WriteAsync(json);

                    }
                    catch (HttpException e)
                    {
                        context.Response.StatusCode = e.StatusCode;
                        return context.Response.WriteAsync(e.Message);
                    }
                    catch (Exception e)
                    {
                        context.Response.StatusCode = 500;
                        var logger = context.RequestServices.GetService<ILogger<CasServerAuthMiddleware>>();
                        logger.LogError(e, "Exception in /cas/.well-known/openid-configuration");
                        return context.Response.WriteAsync("internal server error");
                    }
                });

                // define the keys endpoint
                endpoints.MapGet("/cas/keys", async context =>
                {
                    try
                    {

                        // get all needed variables
                        var tokenIssuer = context.RequestServices.GetService<CasTokenIssuer>();

                        // compute the payload
                        var payload = new KeysPayload();
                        var certificates = await tokenIssuer.GetValidationCertificates();
                        foreach (var certificate in certificates)
                        {
                            var key = new Key(certificate);
                            payload.keys.Add(key);
                        }

                        // return the json
                        string json = JsonSerializer.Serialize(payload);
                        context.Response.Headers.Add("Content-Type", "application/json; charset=utf-8");
                        await context.Response.WriteAsync(json);

                    }
                    catch (HttpException e)
                    {
                        context.Response.StatusCode = e.StatusCode;
                        await context.Response.WriteAsync(e.Message);
                    }
                    catch (Exception e)
                    {
                        context.Response.StatusCode = 500;
                        var logger = context.RequestServices.GetService<ILogger<CasServerAuthMiddleware>>();
                        logger.LogError(e, "Exception in /cas/keys");
                        await context.Response.WriteAsync("internal server error");
                    }
                });

                // define the verify endpoint which determines if an authentication request is valid
                //  note: this can be used for gateways like APIM to validate the request
                endpoints.MapPost("/cas/verify", async context =>
                {
                    try
                    {

                        // get all needed variables
                        var tokenIssuer = context.RequestServices.GetService<CasTokenIssuer>();

                        // find the tokens in the headers
                        string sessionToken = context.Request.Headers["X-SESSION-TOKEN"];
                        if (string.IsNullOrEmpty(sessionToken)) throw new HttpException(400, "X-SESSION-TOKEN header not found");
                        string xsrfToken = context.Request.Headers["X-XSRF-TOKEN"];
                        if (string.IsNullOrEmpty(xsrfToken)) throw new HttpException(400, "X-XSRF-TOKEN header not found");

                        // validate the session_token
                        var validatedSessionToken = await tokenIssuer.ValidateToken(sessionToken);
                        var xsrfclaim = validatedSessionToken.Payload.Claims.FirstOrDefault(c => c.Type == "xsrf");
                        if (xsrfclaim == null) throw new HttpException(400, "xsrf claim not found in X-SESSION-TOKEN");

                        // validate the xsrf_token (if it is signed)
                        string code = xsrfToken;
                        if (xsrfToken.Length > 32)
                        {
                            var validatedXsrfToken = await tokenIssuer.ValidateToken(xsrfToken);
                            var codeclaim = validatedXsrfToken.Payload.Claims.FirstOrDefault(c => c.Type == "code");
                            if (codeclaim == null) throw new HttpException(400, "code claim not found in X-XSRF-TOKEN");
                            code = codeclaim.Value;
                        }

                        // if the code matches, return OK
                        if (xsrfclaim.Value != code) throw new HttpException(403, "xsrf claim does not match code claim");
                        await context.Response.CompleteAsync();

                    }
                    catch (HttpException e)
                    {
                        context.Response.StatusCode = e.StatusCode;
                        await context.Response.WriteAsync(e.Message);
                    }
                    catch (Exception e)
                    {
                        context.Response.StatusCode = 500;
                        var logger = context.RequestServices.GetService<ILogger<CasServerAuthMiddleware>>();
                        logger.LogError(e, "Exception in /cas/verify");
                        await context.Response.WriteAsync("internal server error");
                    }
                });

                // define the type endpoint which shows the selection of authchooser
                endpoints.MapGet("/cas/type", context =>
                {
                    try
                    {
                        switch (CasAuthChooser.AuthType())
                        {
                            case "app":
                                return context.Response.WriteAsync("Application Identity / Service Principal");
                            default:
                                return context.Response.WriteAsync("Managed Identity / az CLI");
                        }
                    }
                    catch (HttpException e)
                    {
                        context.Response.StatusCode = e.StatusCode;
                        return context.Response.WriteAsync(e.Message);
                    }
                    catch (Exception e)
                    {
                        context.Response.StatusCode = 500;
                        var logger = context.RequestServices.GetService<ILogger<CasServerAuthMiddleware>>();
                        logger.LogError(e, "Exception in /cas/type");
                        return context.Response.WriteAsync("internal server error");
                    }
                });

                // define the check-requirements endpoint which ensures that all accounts have appropriate access
                endpoints.MapGet("/cas/check-requirements", async context =>
                {
                    try
                    {

                        // verify graph access
                        var logger = context.RequestServices.GetService<ILogger<CasServerAuthMiddleware>>();
                        var httpClientFactory = context.RequestServices.GetService<IHttpClientFactory>();
                        var httpClient = httpClientFactory.CreateClient("cas");
                        logger.LogInformation("/cas/check-requirements: checking graph access...");
                        var accessToken = await CasAuthChooser.GetAccessToken("https://graph.microsoft.com", "AUTH_TYPE_GRAPH");
                        using (var request = new HttpRequestMessage()
                        {
                            RequestUri = new Uri("https://graph.microsoft.com/beta/users?$top=1"),
                            Method = HttpMethod.Get
                        })
                        {
                            request.Headers.Add("Authorization", $"Bearer {accessToken}");
                            using (var response = await httpClient.SendAsync(request))
                            {
                                if (!response.IsSuccessStatusCode)
                                {
                                    var raw = await response.Content.ReadAsStringAsync();
                                    throw new Exception($"/cas/check-requirements: HTTP {(int)response.StatusCode} - {raw}");
                                }
                            }
                        };
                        logger.LogInformation("/cas/check-requirements: graph access worked as expected.");
                        await context.Response.CompleteAsync();

                    }
                    catch (HttpException e)
                    {
                        context.Response.StatusCode = e.StatusCode;
                        await context.Response.WriteAsync(e.Message);
                    }
                    catch (Exception e)
                    {
                        context.Response.StatusCode = 500;
                        var logger = context.RequestServices.GetService<ILogger<CasServerAuthMiddleware>>();
                        logger.LogError(e, "/cas/check-requirements: exception...");
                        await context.Response.WriteAsync("internal server error");
                    }
                });

                // define the clear-server-cache endpoint
                endpoints.MapPost("/cas/clear-server-cache", async context =>
                {
                    try
                    {

                        // ensure the user is authorized
                        var tokenIssuer = context.RequestServices.GetService<CasTokenIssuer>();
                        var commandPassword = await tokenIssuer.GetCommandPassword();
                        string password = context.Request.Form["password"];
                        if (password != commandPassword) throw new HttpException(401, "user did not provide the valid command password");

                        // clear the caches
                        var logger = context.RequestServices.GetService<ILogger<CasServerAuthMiddleware>>();
                        tokenIssuer.ClearSigningKey();
                        logger.LogDebug("The signing key cache was cleared.");
                        tokenIssuer.ClearValidationCertificates();
                        logger.LogDebug("The validation certificate cache was cleared.");

                        // respond with success
                        await context.Response.CompleteAsync();

                    }
                    catch (HttpException e)
                    {
                        context.Response.StatusCode = e.StatusCode;
                        await context.Response.WriteAsync(e.Message);
                    }
                    catch (Exception e)
                    {
                        context.Response.StatusCode = 500;
                        var logger = context.RequestServices.GetService<ILogger<CasServerAuthMiddleware>>();
                        logger.LogError(e, "Exception in /cas/clear-server-cache");
                        await context.Response.WriteAsync("internal server error");
                    }
                });

            });
            return builder;

        }

    }

}