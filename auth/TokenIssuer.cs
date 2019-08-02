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
using Microsoft.Azure.Services.AppAuthentication;
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

    public static string KeyVaultClientSecretUrl
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("KEYVAULT_CLIENT_SECRET_URL");
        }
    }

    private string _clientSecret;

    public string ClientSecret
    {
        get
        {
            if (string.IsNullOrEmpty(_clientSecret))
            {

                // check for a secret
                if (string.IsNullOrEmpty(KeyVaultClientSecretUrl)) throw new Exception("KEYVAULT_CLIENT_SECRET_URL must be defined");

                // get an access token
                var tokenProvider = new AzureServiceTokenProvider();
                var tokenFetcher = tokenProvider.GetAccessTokenAsync("https://vault.azure.net");
                tokenFetcher.Wait();
                string accessToken = tokenFetcher.Result;

                // get the password
                using (var client = new WebClient())
                {
                    if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
                    client.Headers.Add("Authorization", $"Bearer {accessToken}");
                    string raw = client.DownloadString(new Uri($"{KeyVaultClientSecretUrl}?api-version=7.0"));
                    dynamic json = JObject.Parse(raw);
                    _clientSecret = (string)json.value;
                }

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
                return 0; // forever
            }
        }
    }

    private static string KeyVaultPrivateKeyUrl
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("KEYVAULT_PRIVATE_KEY_URL");
        }
    }

    private static string KeyVaultPrivateKeyPasswordUrl
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("KEYVAULT_PRIVATE_KEY_PASSWORD_URL");
        }
    }

    private static string KeyVaultPublicCertUrl
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("KEYVAULT_PUBLIC_CERT_URL");
        }
    }

    public static bool RequireSecureForCookies
    {
        get
        {
            string v = System.Environment.GetEnvironmentVariable("REQUIRE_SECURE_FOR_COOKIES");
            string[] negative = new string[] { "no", "false", "0" };
            return (!negative.Contains(v));
        }
    }

    private X509SigningCredentials _signingCredentials;

    private X509SigningCredentials SigningCredentials
    {
        get
        {
            if (_signingCredentials == null)
            {

                // get an access token
                var tokenProvider = new AzureServiceTokenProvider();
                var tokenFetcher = tokenProvider.GetAccessTokenAsync("https://vault.azure.net");
                tokenFetcher.Wait();
                string accessToken = tokenFetcher.Result;

                // get the password
                string pw;
                using (var client = new WebClient())
                {
                    if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
                    client.Headers.Add("Authorization", $"Bearer {accessToken}");
                    string raw = client.DownloadString(new Uri($"{KeyVaultPrivateKeyPasswordUrl}?api-version=7.0"));
                    dynamic json = JObject.Parse(raw);
                    pw = (string)json.value;
                }

                // get the private key
                using (var client = new WebClient())
                {
                    if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
                    client.Headers.Add("Authorization", $"Bearer {accessToken}");
                    string raw = client.DownloadString(new Uri($"{KeyVaultPrivateKeyUrl}?api-version=7.0"));
                    dynamic json = JObject.Parse(raw);
                    var bytes = Convert.FromBase64String((string)json.value);
                    var certificate = new X509Certificate2(bytes, pw);
                    _signingCredentials = new X509SigningCredentials(certificate, SecurityAlgorithms.RsaSha256);
                }

            }
            return _signingCredentials;
        }
    }

    private string _validationCertificate;

    public string ValidationCertificate
    {
        get
        {
            if (_validationCertificate == null)
            {

                // get an access token
                var tokenProvider = new AzureServiceTokenProvider();
                var tokenFetcher = tokenProvider.GetAccessTokenAsync("https://vault.azure.net");
                tokenFetcher.Wait();
                string accessToken = tokenFetcher.Result; ;

                // get the certificate
                using (var client = new WebClient())
                {
                    if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
                    client.Headers.Add("Authorization", $"Bearer {accessToken}");
                    string raw = client.DownloadString(new Uri($"{KeyVaultPublicCertUrl}?api-version=7.0"));
                    dynamic json = JObject.Parse(raw);
                    _validationCertificate = (string)json.value;
                }

            }
            return _validationCertificate;
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
        return Convert.FromBase64String(pemString.Substring(start, end));
    }

    private X509SecurityKey _validationKey;

    public X509SecurityKey ValidationKey
    {
        get
        {
            if (_validationKey == null)
            {
                byte[] bytes = GetBytesFromPEM(ValidationCertificate, "CERTIFICATE");
                var certificate = new X509Certificate2(bytes);
                _validationKey = new X509SecurityKey(certificate);
            }
            return _validationKey;
        }
    }

    public async Task<bool> IsUserEnabled(string userId)
    {

        // get an access token
        var tokenProvider = new AzureServiceTokenProvider();
        var accessToken = await tokenProvider.GetAccessTokenAsync("https://graph.microsoft.com");

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

    public async Task<dynamic> GetUserByEmail(string email)
    {

        // get an access token
        var tokenProvider = new AzureServiceTokenProvider();
        var accessToken = await tokenProvider.GetAccessTokenAsync("https://graph.microsoft.com");

        // get the user info
        using (var client = new WebClient())
        {
            if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
            client.Headers.Add("Authorization", $"Bearer {accessToken}");
            string raw = client.DownloadString(new Uri($"https://graph.microsoft.com/beta/users?$filter=mail eq '{email}'"));
            dynamic json = JObject.Parse(raw);
            JArray values = json.value;
            if (values.Count != 1) throw new Exception("a single user could not be found with the supplied email address");
            return values[0];
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
        var tokenProvider = new AzureServiceTokenProvider();
        var accessToken = await tokenProvider.GetAccessTokenAsync("https://graph.microsoft.com");

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
            var numApps = ApplicationIds.Count();
            foreach (var assignment in assignments)
            {
                var appId = (numApps == 1) ? "roles" : assignment.AppId;
                foreach (var role in assignment.Roles)
                {
                    claims.Add(new Claim(appId, role));
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
        JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
        return handler.WriteToken(jwt);

    }

    private JwtSecurityToken IsTokenExpiredButEligibleForRenewal(string token)
    {

        // read the token
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        // shortcut if not expired
        if (DateTime.UtcNow < jwt.Payload.ValidTo.ToUniversalTime()) throw new Exception("token is not expired");

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
                ValidateLifetime = false, // we want to validate everything but the lifetime
                IssuerSigningKey = ValidationKey
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
        bool enabled = await IsUserEnabled((string)oid.Value);
        if (!enabled) throw new Exception("user is not enabled");

        // strip inappropriate claims
        var filter = new string[] { "iss", "aud", "exp" };
        var claims = jwt.Claims.Where(c => !filter.Contains(c.Type)).ToList();

        // reissue the token
        return await IssueToken(claims);

    }

}