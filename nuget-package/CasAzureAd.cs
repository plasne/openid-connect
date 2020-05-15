using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CasAuth
{

    public class CasAzureAd : CasIdp
    {

        public CasAzureAd(
            ILogger<CasAzureAd> logger,
            ICasConfig config,
            CasTokenIssuer tokenIssuer,
            IHttpClientFactory httpClientFactory,
            ICasClaimsBuilder claimsBuilder = null,
            ICasAuthCodeReceiver authCodeReceiver = null
        ) : base(logger, config, tokenIssuer, claimsBuilder, authCodeReceiver)
        {
            this.ConfigManager = new ConfigurationManager<OpenIdConnectConfiguration>($"{CasEnv.AzureAuthority}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
            this.HttpClient = httpClientFactory.CreateClient("cas");
        }

        private ConfigurationManager<OpenIdConnectConfiguration> ConfigManager { get; }
        private HttpClient HttpClient { get; }

        public override string Id { get => "Azure"; }

        public override async Task Authorize(HttpContext context)
        {

            // get the necessary variables
            string authority = CasEnv.AzureAuthority;
            string clientId = WebUtility.UrlEncode(CasEnv.AzureClientId);
            string redirect = WebUtility.UrlEncode(CasEnv.RedirectUri(context.Request));
            string domainHint = WebUtility.UrlEncode(CasEnv.AzureDomainHint);

            // get the scope
            var basicScope = "openid profile email";
            var scope = await AppendScope(basicScope, "microsoft.com");

            // define the response type
            string responseType = (scope == basicScope)
                ? WebUtility.UrlEncode("id_token")
                : WebUtility.UrlEncode("id_token code");

            // write flow cookie
            var flow = WriteFlowCookie(context);

            // redirect to url
            scope = WebUtility.UrlEncode(scope);
            string url = $"{authority}/oauth2/v2.0/authorize?response_type={responseType}&client_id={clientId}&redirect_uri={redirect}&scope={scope}&response_mode=form_post&state={flow.state}&nonce={flow.nonce}";
            if (!string.IsNullOrEmpty(domainHint)) url += $"&domain_hint={domainHint}";
            context.Response.Redirect(url);
            await context.Response.CompleteAsync();

        }

        private class Tokens
        {
            public string access_token { get; set; }
            public string refresh_token { get; set; }
        }

        private async Task<JwtSecurityToken> VerifyTokenFromAAD(string token, string audience = null, string nonce = null)
        {

            // get configuration info from OpenID Connect endpoint
            //  note: this is cached for 1 hour by default
            OpenIdConnectConfiguration config = await ConfigManager.GetConfigurationAsync();

            // determine the possible appropriate issuers
            var issuers = new List<string>();
            string tenant = CasEnv.AzureAuthority.Split("/").LastOrDefault();
            if (tenant == "common")
            {
                // multi-tenant; the issuer will be the directory containing the user
                var handler = new JwtSecurityTokenHandler();
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

            // validate
            var validatedJwt = ValidateTokenFromIdp(token, issuers, audience, nonce, config.SigningKeys);

            return validatedJwt;
        }

        private async Task<Tokens> GetAccessTokenFromAuthCode(HttpContext context, string code, string scope)
        {

            // get the client secret
            var secret = await Config.GetString("CLIENT_SECRET", CasEnv.AzureClientSecret);

            // get the response
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"{CasEnv.AzureAuthority}/oauth2/v2.0/token"),
                Method = HttpMethod.Post
            })
            {
                using (request.Content = new FormUrlEncodedContent(new[] {
                    new KeyValuePair<string, string>("client_id", CasEnv.AzureClientId),
                    new KeyValuePair<string, string>("client_secret", secret),
                    new KeyValuePair<string, string>("scope", scope),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", CasEnv.RedirectUri(context.Request)),
                    new KeyValuePair<string, string>("grant_type", "authorization_code")
                }))
                {
                    using (var response = await HttpClient.SendAsync(request))
                    {
                        var raw = await response.Content.ReadAsStringAsync();
                        if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"GetAccessTokenFromAuthCode: HTTP {(int)response.StatusCode} - {raw}");
                        }
                        var tokens = JsonConvert.DeserializeObject<Tokens>(raw);
                        return tokens;
                    }
                }
            };

        }

        private async Task<Tokens> GetAccessTokenFromRefreshToken(string refreshToken, string scope)
        {

            // get the client secret
            var secret = await Config.GetString("CLIENT_SECRET", CasEnv.AzureClientSecret);

            // get the response
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"{CasEnv.AzureAuthority}/oauth2/v2.0/token"),
                Method = HttpMethod.Post
            })
            {
                using (request.Content = new FormUrlEncodedContent(new[] {
                    new KeyValuePair<string, string>("client_id", CasEnv.AzureClientId),
                    new KeyValuePair<string, string>("client_secret", secret),
                    new KeyValuePair<string, string>("scope", scope),
                    new KeyValuePair<string, string>("refresh_token", refreshToken),
                    new KeyValuePair<string, string>("grant_type", "refresh_token")
                }))
                {
                    using (var response = await HttpClient.SendAsync(request))
                    {
                        var raw = await response.Content.ReadAsStringAsync();
                        if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"GetAccessTokenFromRefreshToken: HTTP {(int)response.StatusCode} - {raw}");
                        }
                        var tokens = JsonConvert.DeserializeObject<Tokens>(raw);
                        return tokens;
                    }
                }
            };

        }

        private async Task<Tokens> GetAccessTokenFromClientSecret(string clientId, string clientSecret, string scope)
        {

            // get the response
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"{CasEnv.AzureAuthority}/oauth2/v2.0/token"),
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
                    using (var response = await HttpClient.SendAsync(request))
                    {
                        var raw = await response.Content.ReadAsStringAsync();
                        if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"GetAccessTokenFromClientSecret: HTTP {(int)response.StatusCode} - {raw}");
                        }
                        var tokens = JsonConvert.DeserializeObject<Tokens>(raw);
                        return tokens;
                    }
                }
            };

        }

        private async Task<Tokens> GetAccessTokenFromClientCertificate(string clientId, string token, string scope)
        {

            // get the response
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"{CasEnv.AzureAuthority}/oauth2/v2.0/token"),
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
                    using (var response = await HttpClient.SendAsync(request))
                    {
                        var raw = await response.Content.ReadAsStringAsync();
                        if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"GetAccessTokenFromClientSecret: HTTP {(int)response.StatusCode} - {raw}");
                        }
                        var tokens = JsonConvert.DeserializeObject<Tokens>(raw);
                        return tokens;
                    }
                }
            };

        }

        private async Task<bool> IsUserEnabled(string userId)
        {

            // get an access token
            var accessToken = await CasAuthChooser.GetAccessToken("https://graph.microsoft.com", "AUTH_TYPE_GRAPH", this.Config);

            // check for enabled
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"https://graph.microsoft.com/beta/users/{userId}?$select=accountEnabled"),
                Method = HttpMethod.Get
            })
            {
                request.Headers.Add("Authorization", $"Bearer {accessToken}");
                using (var response = await this.HttpClient.SendAsync(request))
                {
                    var raw = await response.Content.ReadAsStringAsync();
                    if ((int)response.StatusCode == 403) // Forbidden
                    {
                        throw new Exception("IsUserEnabled: the auth identity does not have the Directory.Read.All right");
                    }
                    else if (!response.IsSuccessStatusCode)
                    {
                        throw new Exception($"IsUserEnabled: HTTP {(int)response.StatusCode} - {raw}");
                    }
                    dynamic json = JObject.Parse(raw);
                    return (bool)json.accountEnabled;
                }
            };

        }

        private async Task<dynamic> GetUserFromGraph(string query)
        {

            // get an access token
            var accessToken = await CasAuthChooser.GetAccessToken("https://graph.microsoft.com", "AUTH_TYPE_GRAPH", this.Config);

            // get the user info
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"https://graph.microsoft.com/beta/users/{query}"),
                Method = HttpMethod.Get
            })
            {
                request.Headers.Add("Authorization", $"Bearer {accessToken}");
                using (var response = await this.HttpClient.SendAsync(request))
                {
                    var raw = await response.Content.ReadAsStringAsync();
                    if ((int)response.StatusCode == 404) // Not Found
                    {
                        return null;
                    }
                    else if ((int)response.StatusCode == 403) // Forbidden
                    {
                        throw new Exception("GetUserById: the auth identity does not have the Directory.Read.All right");
                    }
                    else if (!response.IsSuccessStatusCode)
                    {
                        throw new Exception($"GetUserById: HTTP {(int)response.StatusCode} - {raw}");
                    }
                    dynamic json = JObject.Parse(raw);
                    return json;
                }
            };

        }

        private class RoleAssignments
        {
            public string AppId;
            public List<string> Roles = new List<string>();
        }

        private class AppRoles
        {
            public string AppId;
            public Dictionary<string, string> Roles = new Dictionary<string, string>();
        }

        private async Task<List<RoleAssignments>> GetRoleAssignments(string userId)
        {
            List<RoleAssignments> assignments = new List<RoleAssignments>();

            // get the list of applications to consider for roles
            var appIds = CasEnv.AzureApplicationIds;
            if (appIds.Count() < 1) return assignments;

            // get an access token
            var accessToken = await CasAuthChooser.GetAccessToken("https://graph.microsoft.com", "AUTH_TYPE_GRAPH", this.Config);

            // lookup all specified applications
            //   NOTE: catch the possible 403 Forbidden because access rights have not been granted
            List<AppRoles> apps = new List<AppRoles>();
            string filter = "$filter=" + string.Join(" or ", appIds.Select(appId => $"appId eq '{appId}'"));
            string select = "$select=appId,appRoles";
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"https://graph.microsoft.com/beta/applications/?{filter}&{select}"),
                Method = HttpMethod.Get
            })
            {
                request.Headers.Add("Authorization", $"Bearer {accessToken}");
                using (var response = await this.HttpClient.SendAsync(request))
                {
                    var raw = await response.Content.ReadAsStringAsync();
                    if ((int)response.StatusCode == 403) // Forbidden
                    {
                        throw new Exception("GetRoleAssignments: the auth identity does not have the Directory.Read.All right");
                    }
                    else if (!response.IsSuccessStatusCode)
                    {
                        throw new Exception($"GetRoleAssignments: HTTP {(int)response.StatusCode} - {raw}");
                    }
                    dynamic json = JObject.Parse(raw);
                    var values = (JArray)json.value;
                    foreach (dynamic value in values)
                    {
                        var app = new AppRoles() { AppId = (string)value.appId };
                        apps.Add(app);
                        foreach (dynamic appRole in value.appRoles)
                        {
                            app.Roles.Add((string)appRole.id, (string)appRole.value);
                        }
                    }
                }
            };

            // get the roles that the user is in
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"https://graph.microsoft.com/beta/users/{userId}/appRoleAssignments"),
                Method = HttpMethod.Get
            })
            {
                request.Headers.Add("Authorization", $"Bearer {accessToken}");
                using (var response = await this.HttpClient.SendAsync(request))
                {
                    var raw = await response.Content.ReadAsStringAsync();
                    if ((int)response.StatusCode == 404) // Not Found
                    {
                        // ignore, the user might not be in the directory
                        return assignments;
                    }
                    else if (!response.IsSuccessStatusCode)
                    {
                        throw new Exception($"GetRoleAssignments: HTTP {(int)response.StatusCode} - {raw}");
                    }
                    dynamic json = JObject.Parse(raw);
                    var values = (JArray)json.value;
                    foreach (dynamic value in values)
                    {
                        var appRoleId = (string)value.appRoleId;
                        var app = apps.FirstOrDefault(a => a.Roles.ContainsKey(appRoleId));
                        if (app != null)
                        {
                            var roleName = app.Roles[appRoleId];
                            var existingAssignment = assignments.FirstOrDefault(ra => ra.AppId == app.AppId);
                            if (existingAssignment != null)
                            {
                                existingAssignment.Roles.Add(roleName);
                            }
                            else
                            {
                                var assignment = new RoleAssignments() { AppId = (string)app.AppId };
                                assignment.Roles.Add(roleName);
                                assignments.Add(assignment);
                            }
                        }
                    }
                }
            };

            return assignments;
        }

        public async Task<string> GetOid(JwtSecurityToken idToken, List<Claim> claims)
        {
            if (CasEnv.AzureAuthority.EndsWith("/common"))
            {

                // add the tenant claim
                var tid = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "tid");
                if (tid != null) claims.Add(new Claim("tenant", tid.Value));

                // oids for external users are wrong, we need to query for them
                var oid = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "oid");
                if (oid != null)
                {
                    if (await GetUserFromGraph(oid.Value) == null)
                    {
                        // query by userPrincipalName
                        var username = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "preferred_username");
                        if (username != null)
                        {
                            string userId = username.Value.Replace("@", "_");
                            var users = await GetUserFromGraph($"?$filter=startsWith(userPrincipalName, '{userId}%23EXT%23')");
                            if (users != null && users.value.Count > 0)
                            {
                                var val = (string)users.value[0].id;
                                claims.Add(new Claim("oid", val));
                                return val;
                            }
                        }
                    }
                    else
                    {
                        // the oid was valid; the user is local
                        claims.Add(new Claim("oid", oid.Value));
                        return oid.Value;
                    }
                }

            }
            else
            {

                // oids for 1st party users are fine
                var oid = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "oid");
                if (oid != null)
                {
                    claims.Add(new Claim("oid", oid.Value));
                    return oid.Value;
                }

            }

            return null;
        }

        public override async Task Token(HttpContext context)
        {

            // read flow, verify state and nonce
            if (!context.Request.Cookies.ContainsKey("authflow")) throw new CasHttpException(400, "authflow not provided");
            var flow = JsonConvert.DeserializeObject<CasAuthFlow>(context.Request.Cookies["authflow"]);
            if (context.Request.Form["state"] != flow.state) throw new CasHttpException(400, "state does not match");

            // throw error if one was returned
            if (context.Request.Form.ContainsKey("error_description"))
            {
                throw new CasHttpException(401, context.Request.Form["error_description"]);
            }

            // verify the id token
            string idRaw = context.Request.Form["id_token"];
            var idToken = await VerifyTokenFromAAD(idRaw, CasEnv.AzureClientId, flow.nonce);

            // ICasAuthCodeReceiver: use the code to get an access token
            if (AuthCodeReceiver != null)
            {

                // get code
                string code = context.Request.Form["code"];
                Tokens last = null;

                // get tokens for each scope
                var scopes = await AuthCodeReceiver.GetAllScopes();
                foreach (var scope in scopes)
                {
                    if (last == null)
                    {
                        last = await GetAccessTokenFromAuthCode(context, code, "offline_access " + scope);
                    }
                    else
                    {
                        last = await GetAccessTokenFromRefreshToken(last.refresh_token, "offline_access " + scope);
                    }
                    await AuthCodeReceiver.ReceiveAll(scope, last.access_token, last.refresh_token);
                    break;
                }

            }

            // populate the claims from the id_token
            var claims = BuildClaims(idToken);

            // get the oid
            var oid = await GetOid(idToken, claims);

            // attempt to propogate roles
            var roles = idToken.Payload.Claims.Where(c => c.Type == "roles");
            foreach (var role in roles)
            {
                claims.Add(new Claim("role", role.Value));
            }

            // populate all application roles from the graph
            if (oid != null)
            {
                var assignments = await GetRoleAssignments(oid);
                foreach (var assignment in assignments)
                {
                    foreach (var role in assignment.Roles)
                    {
                        claims.Add(new Claim(assignment.AppId + "-role", role));
                    }
                }
            }

            // apply custom claims
            if (ClaimsBuilder != null)
            {
                await ClaimsBuilder.AddAllClaims(idToken.Payload.Claims, claims);
            }

            // wrote the cookies
            await WriteTokenCookies(context, claims);

            // redirect
            await Redirect(context, flow);

        }

        public override async Task Service(HttpContext context)
        {

            // get all needed variables
            string clientId = context.Request.Form["clientId"];
            string clientSecret = context.Request.Form["clientSecret"];
            string token = context.Request.Form["token"];
            string scope = context.Request.Form["scope"];

            // optionally the call can include a service name which we will assert in the claims
            string serviceName = context.Request.Form["serviceName"];

            // get an access token and verify it
            Tokens tokens = null;
            if (!string.IsNullOrEmpty(token))
            {
                tokens = await GetAccessTokenFromClientCertificate(clientId, token, scope + "/.default");
            }
            else if (!string.IsNullOrEmpty(clientSecret))
            {
                tokens = await GetAccessTokenFromClientSecret(clientId, clientSecret, scope + "/.default");
            }
            else
            {
                throw new Exception("clientSecret or token must be supplied");
            }
            var accessToken = await VerifyTokenFromAAD(tokens.access_token, scope);

            // populate the claims from the id_token
            List<Claim> claims = new List<Claim>();
            var oid = accessToken.Payload.Claims.FirstOrDefault(c => c.Type == "oid");
            if (oid != null) claims.Add(new Claim("oid", oid.Value));

            // add the service details
            if (!string.IsNullOrEmpty(serviceName)) claims.Add(new Claim("name", serviceName));
            claims.Add(new Claim("role", CasEnv.RoleForService));

            // attempt to propogate roles
            var roles = accessToken.Payload.Claims.Where(c => c.Type == "roles");
            foreach (var role in roles)
            {
                claims.Add(new Claim("role", role.Value));
            }

            // return the newly issued token
            string jwt = await TokenIssuer.IssueToken(claims);
            await context.Response.WriteAsync(jwt);
        }

        public override async Task<string> Reissue(string token)
        {

            // make sure the token is eligible
            var jwt = await TokenIssuer.IsTokenExpiredButEligibleForRenewal(token);

            // strip inappropriate claims
            var filter = new string[] { "iss", "aud", "exp" };
            var claims = jwt.Claims.Where(c => !filter.Contains(c.Type)).ToList();

            // make sure the user is eligible
            var oid = claims.FirstOrDefault(claim => claim.Type == "oid");
            if (oid.Value == null) throw new CasHttpException(403, "oid is not specified in the token");
            if (CasEnv.RequireUserEnabledOnReissue)
            {
                bool enabled = await IsUserEnabled((string)oid.Value);
                if (!enabled) throw new CasHttpException(403, "user is not enabled");
            }

            // strip any existing -role claims
            claims.RemoveAll(c => c.Type.EndsWith("-role"));

            // populate all application roles from the graph
            var assignments = await GetRoleAssignments(oid.Value);
            foreach (var assignment in assignments)
            {
                foreach (var role in assignment.Roles)
                {
                    claims.Add(new Claim(assignment.AppId + "-role", role));
                }
            }

            // reissue the token
            return await TokenIssuer.IssueToken(claims);

        }
    }

}