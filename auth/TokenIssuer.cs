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

public class TokenIssuer
{

    public TokenIssuer(ILoggerFactory factory)
    {
        this.Logger = factory.CreateLogger<TokenIssuer>();
    }

    private ILogger Logger { get; }

    public static string Authority
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("AUTHORITY");
        }
    }

    public static string RedirectUri
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("REDIRECT_URI");
        }
    }

    public static string Issuer
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("ISSUER");
        }
    }

    public static string Audience
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("AUDIENCE");
        }
    }

    public static string DefaultRedirectUrl
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("DEFAULT_REDIRECT_URL");
        }
    }

    public static string BaseDomain
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("BASE_DOMAIN");
        }
    }

    public static string[] AllowedOrigins
    {
        get
        {
            string origins = System.Environment.GetEnvironmentVariable("ALLOWED_ORIGINS");
            if (string.IsNullOrEmpty(origins)) return new string[] { };
            return origins.Split(',').Select(id => id.Trim()).ToArray();
        }
    }

    public static string[] ApplicationIds
    {
        get
        {
            // used for determining roles
            string appId = System.Environment.GetEnvironmentVariable("APPLICATION_ID");
            if (string.IsNullOrEmpty(appId)) return new string[] { };
            return appId.Split(',').Select(id => id.Trim()).ToArray();
        }
    }

    public static string DomainHint
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("DOMAIN_HINT");
        }
    }

    public static string ClientId
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("CLIENT_ID");
        }
    }

    private string _clientSecret;

    public string ClientSecret
    {
        get
        {

            // see if there is an env for CLIENT_SECRET
            if (string.IsNullOrEmpty(_clientSecret))
            {
                _clientSecret = System.Environment.GetEnvironmentVariable("CLIENT_SECRET");
            }

            // see if there is an env for KEYVAULT_CLIENT_SECRET_URL
            if (string.IsNullOrEmpty(_clientSecret))
            {
                string url = System.Environment.GetEnvironmentVariable("KEYVAULT_CLIENT_SECRET_URL");
                if (string.IsNullOrEmpty(url)) throw new Exception("either CLIENT_SECRET or KEYVAULT_CLIENT_SECRET_URL must be defined");
                var pw = GetFromKeyVault(url);
                pw.Wait();
                _clientSecret = pw.Result;
            }

            return _clientSecret;
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
        {
            return System.Environment.GetEnvironmentVariable("PUBLIC_KEYS_URL");
        }
    }

    public static bool RequireSecureForCookies
    {
        get
        {
            string v = System.Environment.GetEnvironmentVariable("REQUIRE_SECURE_FOR_COOKIES");
            if (string.IsNullOrEmpty(v)) return true;
            string[] negative = new string[] { "no", "false", "0" };
            return (!negative.Contains(v.ToLower()));
        }
    }

    public static bool RequireUserEnabledOnReissue
    {
        get
        {
            string v = System.Environment.GetEnvironmentVariable("REQUIRE_USER_ENABLED_ON_REISSUE");
            if (string.IsNullOrEmpty(v)) return true;
            string[] negative = new string[] { "no", "false", "0" };
            return (!negative.Contains(v.ToLower()));
        }
    }

    private string _commandPassword;

    public string CommandPassword
    {
        get
        {

            // see if there is an env for COMMAND_PASSWORD
            if (string.IsNullOrEmpty(_commandPassword))
            {
                _commandPassword = System.Environment.GetEnvironmentVariable("COMMAND_PASSWORD");
            }

            // see if there is an env for KEYVAULT_COMMAND_PASSWORD_URL
            if (string.IsNullOrEmpty(_commandPassword))
            {
                string url = System.Environment.GetEnvironmentVariable("KEYVAULT_COMMAND_PASSWORD_URL");
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
            if (string.IsNullOrEmpty(_privateKey))
            {
                _privateKey = System.Environment.GetEnvironmentVariable("PRIVATE_KEY");
            }

            if (string.IsNullOrEmpty(_privateKey))
            {
                string url = System.Environment.GetEnvironmentVariable("KEYVAULT_PRIVATE_KEY_URL");
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
            if (string.IsNullOrEmpty(_privateKeyPw))
            {
                _privateKeyPw = System.Environment.GetEnvironmentVariable("PRIVATE_KEY_PASSWORD");
            }

            if (string.IsNullOrEmpty(_privateKeyPw))
            {
                string url = System.Environment.GetEnvironmentVariable("KEYVAULT_PRIVATE_KEY_PASSWORD_URL");
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
                for (int i = 0; i < 4; i++)
                {
                    string raw = System.Environment.GetEnvironmentVariable($"PUBLIC_CERT_{i}");
                    if (!string.IsNullOrEmpty(raw))
                    {
                        byte[] bytes = GetBytesFromPEM(raw, "CERTIFICATE");
                        var x509 = new X509Certificate2(bytes);
                        _validationCertificates.Add(x509);
                    }
                }

                // attempt to get certificates indexed 0-3 at the same time
                var tasks = new List<Task<string>>();
                string url = System.Environment.GetEnvironmentVariable("KEYVAULT_PUBLIC_CERT_PREFIX_URL");
                if (!string.IsNullOrEmpty(url))
                {
                    for (int i = 0; i < 4; i++)
                    {
                        var task = GetFromKeyVault($"{url}{i}", ignore404: true);
                        tasks.Add(task);
                    }
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
            var accessToken = await AuthChooser.GetAccessToken("https://vault.azure.net");

            // get from the keyvault
            using (var client = new WebClient())
            {
                if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
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
        var accessToken = await AuthChooser.GetAccessToken("https://graph.microsoft.com");

        // check for enabled
        using (var client = new WebClient())
        {
            if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
            client.Headers.Add("Authorization", $"Bearer {accessToken}");
            string raw = client.DownloadString(new Uri($"https://graph.microsoft.com/beta/users/{userId}?$select=accountEnabled"));
            dynamic json = JObject.Parse(raw);
            return (bool)json.accountEnabled;
        }

    }

    public async Task<dynamic> GetUserById(string oid)
    {

        // get an access token
        var accessToken = await AuthChooser.GetAccessToken("https://graph.microsoft.com");

        // get the user info
        using (var client = new WebClient())
        {
            if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
            client.Headers.Add("Authorization", $"Bearer {accessToken}");
            string raw = client.DownloadString(new Uri($"https://graph.microsoft.com/beta/users/{oid}"));
            dynamic json = JObject.Parse(raw);
            return json;
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
        var appIds = ApplicationIds;
        if (appIds.Count() < 1) return assignments;

        // get an access token
        var accessToken = await AuthChooser.GetAccessToken("https://graph.microsoft.com");

        // lookup all specified applications
        List<AppRoles> apps = new List<AppRoles>();
        using (var client = new WebClient())
        {
            if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
            client.Headers.Add("Authorization", $"Bearer {accessToken}");
            string filter = "$filter=" + string.Join(" or ", ApplicationIds.Select(appId => $"appId eq '{appId}'"));
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

        // get the roles that the user is in
        using (var client = new WebClient())
        {
            if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
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

        return assignments;
    }

    public async Task<string> IssueToken(List<Claim> claims)
    {

        // validate that the claims are legitimate
        if (claims.FirstOrDefault(c => c.Type == "iss") != null) throw new Exception("claim cannot contain an issuer");
        if (claims.FirstOrDefault(c => c.Type == "aud") != null) throw new Exception("claim cannot contain an audience");
        if (claims.FirstOrDefault(c => c.Type == "exp") != null) throw new Exception("claim cannot contain an expiration");

        // add the max-age if appropriate
        if (JwtMaxDuration > 0 && claims.FirstOrDefault(c => c.Type == "old") == null)
        {
            claims.Add(new Claim("old", new DateTimeOffset(DateTime.UtcNow).AddMinutes(JwtMaxDuration).ToUnixTimeSeconds().ToString()));
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

        // generate the token
        var jwt = new JwtSecurityToken(
            issuer: Issuer,
            audience: Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(JwtDuration),
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

    private JwtSecurityToken IsTokenExpiredButEligibleForRenewal(string token)
    {

        // read the token
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        // shortcut if not expired
        if (DateTime.UtcNow < jwt.Payload.ValidTo.ToUniversalTime()) throw new Exception("token is not expired");

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
                ValidIssuer = Issuer,
                ValidateAudience = true,
                ValidAudience = Audience,
                ValidateIssuerSigningKey = true,
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
        if (RequireUserEnabledOnReissue)
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