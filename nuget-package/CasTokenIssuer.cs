using System;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Net.Http;

namespace CasAuth
{

    public class CasTokenIssuer
    {

        public CasTokenIssuer(ILogger<CasTokenIssuer> logger, IHttpClientFactory httpClientFactory)
        {
            this.Logger = logger;
            this.HttpClient = httpClientFactory.CreateClient("cas");
            this.ConfigManager = new ConfigurationManager<OpenIdConnectConfiguration>($"{CasEnv.Authority}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
        }

        private ILogger Logger { get; }
        private HttpClient HttpClient { get; }
        public ConfigurationManager<OpenIdConnectConfiguration> ConfigManager { get; }

        private string _clientSecret;

        public async Task<string> GetClientSecret()
        {

            // see if there is an env for CLIENT_SECRET
            if (string.IsNullOrEmpty(_clientSecret)) _clientSecret = CasEnv.ClientSecret;

            // see if there is an env for KEYVAULT_CLIENT_SECRET_URL
            if (string.IsNullOrEmpty(_clientSecret))
            {
                string url = CasEnv.KeyvaultClientSecretUrl;
                if (string.IsNullOrEmpty(url)) throw new Exception("either CLIENT_SECRET or KEYVAULT_CLIENT_SECRET_URL must be defined");
                _clientSecret = await CasTokenIssuer.GetFromKeyVault(this.HttpClient, url);
            }

            return _clientSecret;
        }

        private string _clientSecretGraph;

        public async Task<string> GetClientSecretGraph()
        {

            // see if there is an env for CLIENT_SECRET_GRAPH
            if (string.IsNullOrEmpty(_clientSecretGraph)) _clientSecretGraph = CasEnv.ClientSecret;

            // see if there is an env for KEYVAULT_CLIENT_SECRET_GRAPH_URL
            if (string.IsNullOrEmpty(_clientSecretGraph))
            {
                string url = CasEnv.KeyvaultClientSecretGraphUrl;
                if (!string.IsNullOrEmpty(url))
                {
                    _clientSecretGraph = await CasTokenIssuer.GetFromKeyVault(this.HttpClient, url);
                }
                else
                {
                    _clientSecretGraph = await GetClientSecret();
                }
            }

            return _clientSecretGraph;
        }

        private string _commandPassword;

        public async Task<string> GetCommandPassword()
        {

            // see if there is an env for COMMAND_PASSWORD
            if (string.IsNullOrEmpty(_commandPassword)) _commandPassword = CasEnv.CommandPassword;

            // see if there is an env for KEYVAULT_COMMAND_PASSWORD_URL
            if (string.IsNullOrEmpty(_commandPassword))
            {
                string url = CasEnv.KeyvaultCommandPasswordUrl;
                if (!string.IsNullOrEmpty(url))
                {
                    _commandPassword = await CasTokenIssuer.GetFromKeyVault(this.HttpClient, url);
                }
            }

            return _commandPassword;
        }

        private string _privateKey;

        public async Task<string> GetPrivateKey()
        {

            // see if there is an env for PRIVATE_KEY
            if (string.IsNullOrEmpty(_privateKey)) _privateKey = CasEnv.PrivateKey;

            // see if there is an env for KEYVAULT_PRIVATE_KEY_URL
            if (string.IsNullOrEmpty(_privateKey))
            {
                string url = CasEnv.KeyvaultPrivateKeyUrl;
                if (string.IsNullOrEmpty(url)) throw new Exception("either PRIVATE_KEY or KEYVAULT_PRIVATE_KEY_URL must be defined");
                _privateKey = await CasTokenIssuer.GetFromKeyVault(this.HttpClient, url);
            }

            return _privateKey;
        }

        private string _privateKeyPw;

        public async Task<string> GetPrivateKeyPassword()
        {

            // see if there is an env for PRIVATE_KEY
            if (string.IsNullOrEmpty(_privateKeyPw)) _privateKeyPw = CasEnv.PrivateKeyPassword;

            if (string.IsNullOrEmpty(_privateKeyPw))
            {
                string url = CasEnv.KeyvaultPrivateKeyPasswordUrl;
                if (string.IsNullOrEmpty(url)) throw new Exception("either PRIVATE_KEY_PASSWORD or KEYVAULT_PRIVATE_KEY_PASSWORD_URL must be defined");
                _privateKeyPw = await CasTokenIssuer.GetFromKeyVault(this.HttpClient, url);
            }

            return _privateKeyPw;
        }

        private X509SigningCredentials _signingCredentials;

        private async Task<X509SigningCredentials> GetSigningCredentials()
        {
            if (_signingCredentials == null)
            {
                var privateKey = await GetPrivateKey();
                var bytes = Convert.FromBase64String(privateKey);
                var privateKeyPassword = await GetPrivateKeyPassword();
                var certificate = new X509Certificate2(bytes, privateKeyPassword);
                _signingCredentials = new X509SigningCredentials(certificate, SecurityAlgorithms.RsaSha256);
            }
            return _signingCredentials;
        }

        private List<X509Certificate2> _validationCertificates;

        public async Task<List<X509Certificate2>> GetValidationCertificates()
        {
            if (_validationCertificates == null)
            {
                _validationCertificates = new List<X509Certificate2>();

                // attempt to read from environment variables
                foreach (string raw in CasEnv.PublicCertificates)
                {
                    byte[] bytes = GetBytesFromPEM(raw, "CERTIFICATE");
                    var x509 = new X509Certificate2(bytes);
                    _validationCertificates.Add(x509);
                }

                // attempt to get certificates indexed 0-3 at the same time
                var tasks = new List<Task<string>>();
                foreach (string url in CasEnv.KeyvaultPublicCertificateUrls)
                {
                    var task = GetFromKeyVault(this.HttpClient, url, ignore404: true);
                    tasks.Add(task);
                }

                // wait for all the tasks to complete
                await Task.WhenAll(tasks.ToArray());

                // add to certificates
                foreach (var task in tasks)
                {
                    if (!string.IsNullOrEmpty(task.Result))
                    {
                        byte[] bytes = GetBytesFromPEM(task.Result, "CERTIFICATE");
                        var x509 = new X509Certificate2(bytes);
                        _validationCertificates.Add(x509);
                    }
                }

                // make sure there is at least 1
                if (_validationCertificates.Count() < 1) throw new Exception("there are no PUBLIC_CERT_# variables defined");

            }
            return _validationCertificates;
        }

        private static async Task<string> GetFromKeyVault(HttpClient httpClient, string url, bool ignore404 = false)
        {

            // get an access token
            var accessToken = await CasAuthChooser.GetAccessToken("https://vault.azure.net", "AUTH_TYPE_VAULT");

            // get from the keyvault
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"{url}?api-version=7.0"),
                Method = HttpMethod.Get
            })
            {
                request.Headers.Add("Authorization", $"Bearer {accessToken}");
                using (var response = await httpClient.SendAsync(request))
                {
                    var raw = await response.Content.ReadAsStringAsync();
                    if (ignore404 && (int)response.StatusCode == 404) // Not Found
                    {
                        return string.Empty;
                    }
                    else if (!response.IsSuccessStatusCode)
                    {
                        throw new Exception($"CasTokenIssuer.GetFromKeyVault: HTTP {(int)response.StatusCode} - {raw}");
                    }
                    dynamic json = JObject.Parse(raw);
                    return (string)json.value;
                }
            };

        }

        private static byte[] GetBytesFromPEM(string pemString, string section = "CERTIFICATE")
        {
            var header = String.Format("-----BEGIN {0}-----", section);
            var footer = String.Format("-----END {0}-----", section);
            var start = pemString.IndexOf(header, StringComparison.Ordinal);
            if (start < 0) return null;
            start += header.Length;
            var end = pemString.IndexOf(footer, start, StringComparison.Ordinal) - start;
            if (end < 0) return null;
            string body = pemString.Substring(start, end).Trim();
            return Convert.FromBase64String(body);
        }

        public void ClearSigningKey()
        {
            _signingCredentials = null;
        }

        public void ClearValidationCertificates()
        {
            _validationCertificates = null;
        }

        public async Task<bool> IsUserEnabled(string userId)
        {

            // get an access token
            var accessToken = await CasAuthChooser.GetAccessToken("https://graph.microsoft.com", "AUTH_TYPE_GRAPH", this);

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
                        throw new Exception("CasTokenIssuer.IsUserEnabled: the auth identity does not have the Directory.Read.All right");
                    }
                    else if (!response.IsSuccessStatusCode)
                    {
                        throw new Exception($"CasTokenIssuer.IsUserEnabled: HTTP {(int)response.StatusCode} - {raw}");
                    }
                    dynamic json = JObject.Parse(raw);
                    return (bool)json.accountEnabled;
                }
            };

        }

        public async Task<dynamic> GetUserFromGraph(string query)
        {

            // get an access token
            var accessToken = await CasAuthChooser.GetAccessToken("https://graph.microsoft.com", "AUTH_TYPE_GRAPH", this);

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
                        throw new Exception("CasTokenIssuer.GetUserById: the auth identity does not have the Directory.Read.All right");
                    }
                    else if (!response.IsSuccessStatusCode)
                    {
                        throw new Exception($"CasTokenIssuer.GetUserById: HTTP {(int)response.StatusCode} - {raw}");
                    }
                    dynamic json = JObject.Parse(raw);
                    return json;
                }
            };

        }

        public class RoleAssignments
        {
            public string AppId;
            public List<string> Roles = new List<string>();
        }

        private class AppRoles
        {
            public string AppId;
            public Dictionary<string, string> Roles = new Dictionary<string, string>();
        }

        public async Task<List<RoleAssignments>> GetRoleAssignments(string userId)
        {
            List<RoleAssignments> assignments = new List<RoleAssignments>();

            // get the list of applications to consider for roles
            var appIds = CasEnv.ApplicationIds;
            if (appIds.Count() < 1) return assignments;

            // get an access token
            var accessToken = await CasAuthChooser.GetAccessToken("https://graph.microsoft.com", "AUTH_TYPE_GRAPH", this);

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
                        throw new Exception("CasTokenIssuer.GetRoleAssignments: the auth identity does not have the Directory.Read.All right");
                    }
                    else if (!response.IsSuccessStatusCode)
                    {
                        throw new Exception($"CasTokenIssuer.GetRoleAssignments: HTTP {(int)response.StatusCode} - {raw}");
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
                        throw new Exception($"CasTokenIssuer.GetRoleAssignments: HTTP {(int)response.StatusCode} - {raw}");
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

        public async Task<string> IssueToken(List<Claim> claims)
        {

            // validate that the claims are legitimate
            if (claims.FirstOrDefault(c => c.Type == "iss") != null) throw new Exception("claim cannot contain an issuer");
            if (claims.FirstOrDefault(c => c.Type == "aud") != null) throw new Exception("claim cannot contain an audience");
            if (claims.FirstOrDefault(c => c.Type == "exp") != null) throw new Exception("claim cannot contain an expiration");

            // add the max-age if appropriate
            if (CasEnv.JwtMaxDuration > 0 && claims.FirstOrDefault(c => c.Type == "old") == null)
            {
                claims.Add(new Claim("old", new DateTimeOffset(DateTime.UtcNow).AddMinutes(CasEnv.JwtMaxDuration).ToUnixTimeSeconds().ToString()));
            }

            // populate all application roles
            var oid = claims.FirstOrDefault(c => c.Type == "oid");
            if (oid != null)
            {
                var assignments = await GetRoleAssignments(oid.Value);
                foreach (var assignment in assignments)
                {
                    foreach (var role in assignment.Roles)
                    {
                        claims.Add(new Claim(assignment.AppId + "-roles", role));
                    }
                }
            }

            // determine the signing duration
            var duration = (claims.IsService()) ? CasEnv.JwtServiceDuration : CasEnv.JwtDuration;

            // get the signing creds
            var signingCredentials = await GetSigningCredentials();

            // generate the token
            var jwt = new JwtSecurityToken(
                issuer: CasEnv.Issuer,
                audience: CasEnv.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(duration),
                signingCredentials: signingCredentials);

            // serialize
            try
            {
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                return handler.WriteToken(jwt);
            }
            catch (Exception e)
            {
                if (e.Message.Contains("The system cannot find the file specified"))
                {
                    throw new Exception("The User Profile is not available - https://github.com/projectkudu/kudu/wiki/Configurable-settings#the-system-cannot-find-the-file-specified-issue-with-x509certificate2", e);
                }
                else
                {
                    throw;
                }
            }

        }

        public async Task<string> IssueXsrfToken(string code)
        {

            // add the claims
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("code", code));

            // get the signing creds
            var signingCredentials = await GetSigningCredentials();

            // generate the token
            var jwt = new JwtSecurityToken(
                issuer: CasEnv.Issuer,
                audience: CasEnv.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(CasEnv.JwtMaxDuration).AddMinutes(60), // good beyond the max-duration
                signingCredentials: signingCredentials);

            // serialize
            try
            {
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                return handler.WriteToken(jwt);
            }
            catch (Exception e)
            {
                if (e.Message.Contains("The system cannot find the file specified"))
                {
                    throw new Exception("The User Profile is not available - https://github.com/projectkudu/kudu/wiki/Configurable-settings#the-system-cannot-find-the-file-specified-issue-with-x509certificate2", e);
                }
                else
                {
                    throw;
                }
            }

        }

        public async Task<JwtSecurityToken> ValidateToken(string token)
        {

            // get keys from certificates
            var certs = await GetValidationCertificates();
            var keys = certs.Select(c => new X509SecurityKey(c));

            // parameters to validate
            var handler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuer = CasEnv.Issuer,
                ValidateAudience = true,
                ValidAudience = CasEnv.Audience,
                ValidateLifetime = true,
                IssuerSigningKeys = keys
            };

            // validate all previously defined parameters
            SecurityToken validatedSecurityToken = null;
            handler.ValidateToken(token, validationParameters, out validatedSecurityToken);
            JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;

            return validatedJwt;
        }

        private async Task<JwtSecurityToken> IsTokenExpiredButEligibleForRenewal(string token)
        {

            // read the token
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);

            // shortcut if not expired
            if (DateTime.UtcNow < jwt.Payload.ValidTo.ToUniversalTime()) throw new CasHttpException(400, "token is not expired");

            // make sure it is not a service account
            if (jwt.Payload.Claims.IsService()) throw new CasHttpException(403, "only user tokens can be reissued");

            // get keys from certificates
            var certs = await GetValidationCertificates();
            var keys = certs.Select(c => new X509SecurityKey(c));

            // validate everything but the expiry
            SecurityToken validatedSecurityToken = null;
            try
            {
                handler.ValidateToken(token, new TokenValidationParameters
                {
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidateIssuer = true,
                    ValidIssuer = CasEnv.Issuer,
                    ValidateAudience = true,
                    ValidAudience = CasEnv.Audience,
                    ValidateLifetime = false, // we want to validate everything but the lifetime
                    IssuerSigningKeys = keys
                }, out validatedSecurityToken);
            }
            catch (Exception e)
            {
                throw new CasHttpException(400, "token cannot be validated (excepting lifetime) - " + e.Message);
            }
            JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;

            // tokens are only eligible up to a defined age
            var old = jwt.Payload.FirstOrDefault(claim => claim.Key == "old");
            if (old.Value == null) return validatedJwt; // no max-age, so it is eligible
            if (!long.TryParse((string)old.Value, out long oldAsLong)) throw new Exception("token max-age cannot be determined");
            var max = DateTimeOffset.FromUnixTimeSeconds(oldAsLong).UtcDateTime;
            if (DateTime.UtcNow < max)
            {
                return validatedJwt;
            }
            else
            {
                throw new CasHttpException(403, "token is too old to renew");
            }

        }

        public async Task<string> ReissueToken(string token)
        {

            // make sure the token is eligible
            var jwt = await IsTokenExpiredButEligibleForRenewal(token);

            // make sure the user is eligible
            var oid = jwt.Payload.FirstOrDefault(claim => claim.Key == "oid");
            if (oid.Value == null) throw new CasHttpException(403, "oid is not specified in the token");
            if (CasEnv.RequireUserEnabledOnReissue)
            {
                bool enabled = await IsUserEnabled((string)oid.Value);
                if (!enabled) throw new CasHttpException(403, "user is not enabled");
            }

            // strip inappropriate claims
            var filter = new string[] { "iss", "aud", "exp" }; // note: the "roles" claim is left if that were pulled from the id_token
            var claims = jwt.Claims.Where(c => !filter.Contains(c.Type) && !c.Type.EndsWith("-roles")).ToList();

            // reissue the token
            return await IssueToken(claims);

        }

    }

}