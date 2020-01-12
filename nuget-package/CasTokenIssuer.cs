using System;
using System.Linq;
using System.Threading.Tasks;
using System.Net;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace CasAuth
{

    public class CasTokenIssuer
    {

        public CasTokenIssuer(ILogger<CasTokenIssuer> logger)
        {
            this.Logger = logger;
            this.ConfigManager = new ConfigurationManager<OpenIdConnectConfiguration>($"{CasEnv.Authority}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
        }

        private ILogger Logger { get; }
        public ConfigurationManager<OpenIdConnectConfiguration> ConfigManager { get; }

        private string _clientSecret;

        public string ClientSecret
        {
            get
            {

                // see if there is an env for CLIENT_SECRET
                if (string.IsNullOrEmpty(_clientSecret)) _clientSecret = CasEnv.ClientSecret;

                // see if there is an env for KEYVAULT_CLIENT_SECRET_URL
                if (string.IsNullOrEmpty(_clientSecret))
                {
                    string url = CasEnv.KeyvaultClientSecretUrl;
                    if (string.IsNullOrEmpty(url)) throw new Exception("either CLIENT_SECRET or KEYVAULT_CLIENT_SECRET_URL must be defined");
                    var pw = GetFromKeyVault(url);
                    pw.Wait();
                    _clientSecret = pw.Result;
                }

                return _clientSecret;
            }
        }

        private string _commandPassword;

        public string CommandPassword
        {
            get
            {

                // see if there is an env for COMMAND_PASSWORD
                if (string.IsNullOrEmpty(_commandPassword)) _commandPassword = CasEnv.CommandPassword;

                // see if there is an env for KEYVAULT_COMMAND_PASSWORD_URL
                if (string.IsNullOrEmpty(_commandPassword))
                {
                    string url = CasEnv.KeyvaultCommandPasswordUrl;
                    if (!string.IsNullOrEmpty(url))
                    {
                        var pw = GetFromKeyVault(url);
                        pw.Wait();
                        _commandPassword = pw.Result;
                    }
                }

                return _commandPassword;
            }
        }

        private string _privateKey;

        public string PrivateKey
        {
            get
            {

                // see if there is an env for PRIVATE_KEY
                if (string.IsNullOrEmpty(_privateKey)) _privateKey = CasEnv.PrivateKey;

                if (string.IsNullOrEmpty(_privateKey))
                {
                    string url = CasEnv.KeyvaultPrivateKeyUrl;
                    if (string.IsNullOrEmpty(url)) throw new Exception("either PRIVATE_KEY or KEYVAULT_PRIVATE_KEY_URL must be defined");
                    var key = GetFromKeyVault(url);
                    key.Wait();
                    _privateKey = key.Result;
                }

                return _privateKey;
            }
        }

        private string _privateKeyPw;

        public string PrivateKeyPassword
        {
            get
            {

                // see if there is an env for PRIVATE_KEY
                if (string.IsNullOrEmpty(_privateKeyPw)) _privateKeyPw = CasEnv.PrivateKeyPassword;

                if (string.IsNullOrEmpty(_privateKeyPw))
                {
                    string url = CasEnv.KeyvaultPrivateKeyPasswordUrl;
                    if (string.IsNullOrEmpty(url)) throw new Exception("either PRIVATE_KEY_PASSWORD or KEYVAULT_PRIVATE_KEY_PASSWORD_URL must be defined");
                    var key = GetFromKeyVault(url);
                    key.Wait();
                    _privateKeyPw = key.Result;
                }

                return _privateKeyPw;
            }
        }

        private X509SigningCredentials _signingCredentials;

        private X509SigningCredentials SigningCredentials
        {
            get
            {
                if (_signingCredentials == null)
                {
                    var bytes = Convert.FromBase64String(PrivateKey);
                    var certificate = new X509Certificate2(bytes, PrivateKeyPassword);
                    _signingCredentials = new X509SigningCredentials(certificate, SecurityAlgorithms.RsaSha256);
                }
                return _signingCredentials;
            }
        }

        private List<X509Certificate2> _validationCertificates;

        public List<X509Certificate2> ValidationCertificates
        {
            get
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
                        var task = GetFromKeyVault(url, ignore404: true);
                        tasks.Add(task);
                    }

                    // wait for all the tasks to complete
                    Task.WaitAll(tasks.ToArray());

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
        }

        private async Task<string> GetFromKeyVault(string url, bool ignore404 = false)
        {
            try
            {

                // get an access token
                var accessToken = await CasAuthChooser.GetAccessToken("https://vault.azure.net", "AUTH_TYPE_VAULT");

                // get from the keyvault
                using (var client = new WebClient())
                {
                    if (!string.IsNullOrEmpty(CasEnv.Proxy)) client.Proxy = new WebProxy(CasEnv.Proxy);
                    client.Headers.Add("Authorization", $"Bearer {accessToken}");
                    string raw = client.DownloadString(new Uri($"{url}?api-version=7.0"));
                    dynamic json = JObject.Parse(raw);
                    return (string)json.value;
                }

            }
            catch (WebException e)
            {
                if (ignore404 && e.Response != null && ((HttpWebResponse)e.Response).StatusCode == HttpStatusCode.NotFound)
                {
                    return string.Empty; // 404 Not Found is acceptible
                }
                else
                {
                    throw;
                }
            }
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
            var accessToken = await CasAuthChooser.GetAccessToken("https://graph.microsoft.com", "AUTH_TYPE_GRAPH");

            // catch the possible 403 Forbidden because access rights have not been granted
            try
            {

                // check for enabled
                using (var client = new WebClient())
                {
                    if (!string.IsNullOrEmpty(CasEnv.Proxy)) client.Proxy = new WebProxy(CasEnv.Proxy);
                    client.Headers.Add("Authorization", $"Bearer {accessToken}");
                    string raw = client.DownloadString(new Uri($"https://graph.microsoft.com/beta/users/{userId}?$select=accountEnabled"));
                    dynamic json = JObject.Parse(raw);
                    return (bool)json.accountEnabled;
                }

            }
            catch (WebException e)
            {
                if (e.Response != null && ((HttpWebResponse)e.Response).StatusCode == HttpStatusCode.Forbidden)
                {
                    throw new Exception("the auth identity does not have the Directory.Read.All right", e);
                }
                else
                {
                    throw;
                }
            }

        }

        public async Task<dynamic> GetUserById(string query)
        {

            // get an access token
            var accessToken = await CasAuthChooser.GetAccessToken("https://graph.microsoft.com", "AUTH_TYPE_GRAPH");

            // get the user info
            try
            {
                using (var client = new WebClient())
                {
                    if (!string.IsNullOrEmpty(CasEnv.Proxy)) client.Proxy = new WebProxy(CasEnv.Proxy);
                    client.Headers.Add("Authorization", $"Bearer {accessToken}");
                    string raw = client.DownloadString(new Uri($"https://graph.microsoft.com/beta/users/{query}"));
                    dynamic json = JObject.Parse(raw);
                    return json;
                }
            }
            catch (WebException e)
            {
                if (e.Response != null && ((HttpWebResponse)e.Response).StatusCode == HttpStatusCode.NotFound)
                {
                    // the user was not found, but the query was valid
                    return null;
                }
                else if (e.Response != null && ((HttpWebResponse)e.Response).StatusCode == HttpStatusCode.Forbidden)
                {
                    throw new Exception("the auth identity does not have the Directory.Read.All right", e);
                }
                else
                {
                    throw;
                }
            }
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
            var accessToken = await CasAuthChooser.GetAccessToken("https://graph.microsoft.com", "AUTH_TYPE_GRAPH");

            // lookup all specified applications
            //   NOTE: catch the possible 403 Forbidden because access rights have not been granted
            List<AppRoles> apps = new List<AppRoles>();
            try
            {
                using (var client = new WebClient())
                {
                    if (!string.IsNullOrEmpty(CasEnv.Proxy)) client.Proxy = new WebProxy(CasEnv.Proxy);
                    client.Headers.Add("Authorization", $"Bearer {accessToken}");
                    string filter = "$filter=" + string.Join(" or ", appIds.Select(appId => $"appId eq '{appId}'"));
                    string select = "$select=appId,appRoles";
                    string raw = client.DownloadString(new Uri($"https://graph.microsoft.com/beta/applications/?{filter}&{select}"));
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
            }
            catch (WebException e)
            {
                if (e.Response != null && ((HttpWebResponse)e.Response).StatusCode == HttpStatusCode.Forbidden)
                {
                    throw new Exception("the auth identity does not have the Directory.Read.All right", e);
                }
                else
                {
                    throw;
                }
            }

            // get the roles that the user is in
            try
            {
                using (var client = new WebClient())
                {
                    if (!string.IsNullOrEmpty(CasEnv.Proxy)) client.Proxy = new WebProxy(CasEnv.Proxy);
                    client.Headers.Add("Authorization", $"Bearer {accessToken}");
                    string raw = client.DownloadString(new Uri($"https://graph.microsoft.com/beta/users/{userId}/appRoleAssignments"));
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
            }
            catch (WebException e)
            {
                if (e.Response != null && ((HttpWebResponse)e.Response).StatusCode == HttpStatusCode.NotFound)
                {
                    // ignore, the user might not be in the directory
                }
                else if (e.Response != null && ((HttpWebResponse)e.Response).StatusCode == HttpStatusCode.Forbidden)
                {
                    throw new Exception("the auth identity does not have the Directory.Read.All right", e);
                }
                else
                {
                    throw;
                }
            }

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
            var typ = claims.FirstOrDefault(c => c.Type == "typ");
            var duration = (typ != null && typ.Value == "service") ? CasEnv.JwtServiceDuration : CasEnv.JwtDuration;

            // generate the token
            var jwt = new JwtSecurityToken(
                issuer: CasEnv.Issuer,
                audience: CasEnv.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(duration),
                signingCredentials: SigningCredentials);

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

        public string IssueXsrfToken(string code)
        {

            // add the claims
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("code", code));

            // generate the token
            var jwt = new JwtSecurityToken(
                issuer: CasEnv.Issuer,
                audience: CasEnv.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(CasEnv.JwtMaxDuration).AddMinutes(60), // good beyond the max-duration
                signingCredentials: SigningCredentials);

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

        public JwtSecurityToken ValidateToken(string token)
        {

            // get keys from certificates
            var keys = ValidationCertificates.Select(c => new X509SecurityKey(c));

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

        private JwtSecurityToken IsTokenExpiredButEligibleForRenewal(string token)
        {

            // read the token
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);

            // shortcut if not expired
            if (DateTime.UtcNow < jwt.Payload.ValidTo.ToUniversalTime()) throw new Exception("token is not expired");

            // make sure it is typ=user
            var typ = jwt.Payload.Claims.FirstOrDefault(c => c.Type == "typ");
            if (typ == null || typ.Value != "user") throw new Exception("only user tokens can be reissued");

            // get keys from certificates
            var keys = ValidationCertificates.Select(c => new X509SecurityKey(c));

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
                throw new Exception("token cannot be validated (excepting lifetime)", e);
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
                throw new Exception("token is too old to renew");
            }

        }

        public async Task<string> ReissueToken(string token)
        {

            // make sure the token is eligible
            var jwt = IsTokenExpiredButEligibleForRenewal(token);

            // make sure the user is eligible
            var oid = jwt.Payload.FirstOrDefault(claim => claim.Key == "oid");
            if (oid.Value == null) throw new Exception("oid is not specified in the token");
            if (CasEnv.RequireUserEnabledOnReissue)
            {
                bool enabled = await IsUserEnabled((string)oid.Value);
                if (!enabled) throw new Exception("user is not enabled");
            }

            // strip inappropriate claims
            var filter = new string[] { "iss", "aud", "exp" }; // note: the "roles" claim is left if that were pulled from the id_token
            var claims = jwt.Claims.Where(c => !filter.Contains(c.Type) && !c.Type.EndsWith("-roles")).ToList();

            // reissue the token
            return await IssueToken(claims);

        }

    }

}