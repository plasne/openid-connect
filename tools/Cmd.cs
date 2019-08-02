using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Identity.Client;
using System.Net;
using Newtonsoft.Json.Linq;
using System.Threading.Tasks;
using Microsoft.Azure.Services.AppAuthentication;

public class Cmd
{

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

    public static string KeyVaultPrivateKeyUrl
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("KEYVAULT_PRIVATE_KEY_URL");
        }
    }

    public static string KeyVaultPrivateKeyPasswordUrl
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("KEYVAULT_PRIVATE_KEY_PASSWORD_URL");
        }
    }

    private int _jwtDuration;

    public int JwtDuration
    {
        get
        {
            if (_jwtDuration > 0) return _jwtDuration;
            string env = System.Environment.GetEnvironmentVariable("JWT_DURATION");
            int envAsInt;
            if (int.TryParse(env, out envAsInt)) return envAsInt;
            return 4 * 60; // 4 hour default
        }
        set
        {
            _jwtDuration = value;
        }
    }

    private int _jwtMaxDuration;

    public int JwtMaxDuration
    {
        get
        {
            if (_jwtMaxDuration > 0) return _jwtMaxDuration;
            string env = System.Environment.GetEnvironmentVariable("JWT_MAX_DURATION");
            int envAsInt;
            if (int.TryParse(env, out envAsInt)) return envAsInt;
            return 7 * 24 * 60; // 7 day default
        }
        set
        {
            _jwtMaxDuration = value;
        }
    }

    private string _xsrf;

    public string Xsrf
    {
        get
        {
            if (!string.IsNullOrEmpty(_xsrf)) return _xsrf;
            return System.Environment.GetEnvironmentVariable("XSRF");
        }
        set
        {
            _xsrf = value;
        }
    }

    public async Task IssueToken(string oid, string displayName, string email, IEnumerable<string> roles)
    {

        // get an access token to keyvault
        var tokenProvider = new AzureServiceTokenProvider();
        string accessToken = await tokenProvider.GetAccessTokenAsync("https://vault.azure.net");

        // get the password for the private key
        string password;
        using (var client = new WebClient())
        {
            if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
            client.Headers.Add("Authorization", $"Bearer {accessToken}");
            string raw = client.DownloadString(new Uri($"{KeyVaultPrivateKeyPasswordUrl}?api-version=7.0"));
            dynamic json = JObject.Parse(raw);
            password = (string)json.value;
        }

        // get the private key
        byte[] key;
        using (var client = new WebClient())
        {
            if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
            client.Headers.Add("Authorization", $"Bearer {accessToken}");
            string raw = client.DownloadString(new Uri($"{KeyVaultPrivateKeyUrl}?api-version=7.0"));
            dynamic json = JObject.Parse(raw);
            key = Convert.FromBase64String((string)json.value);
        }

        // populate the claims
        List<Claim> claims = new List<Claim>();
        claims.Add(new Claim("oid", oid));
        claims.Add(new Claim("displayName", displayName));
        claims.Add(new Claim("email", email));
        claims.Add(new Claim("xsrf", Xsrf));
        var oldOffset = new DateTimeOffset(DateTime.UtcNow).AddMinutes(JwtMaxDuration);
        claims.Add(new Claim("old", oldOffset.ToUnixTimeSeconds().ToString()));
        foreach (string role in roles)
        {
            claims.Add(new Claim("roles", role));
        }

        // sign the token
        var certificate = new X509Certificate2(key, password);
        var creds = new X509SigningCredentials(certificate, SecurityAlgorithms.RsaSha256);

        // generate the token
        var jwt = new JwtSecurityToken(
            issuer: Issuer,
            audience: Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(JwtDuration),
            signingCredentials: creds);

        // write to string
        JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
        string jwt_s = handler.WriteToken(jwt);

        // write the output
        Console.WriteLine("");
        Console.WriteLine(jwt_s);
        Console.WriteLine("");
        Console.WriteLine(jwt.Payload.SerializeToJson());
        Console.WriteLine("");
        Console.WriteLine($"from: {jwt.ValidFrom}");
        Console.WriteLine($"to: {jwt.ValidTo.ToUniversalTime()}");
        Console.WriteLine($"old: {oldOffset.ToUniversalTime()}");
        Console.WriteLine($"len: {jwt_s.Length}");

    }

    public async Task ValidateToken(string token)
    {

        // get an access token for keyvault
        var tokenProvider = new AzureServiceTokenProvider();
        var accessToken = await tokenProvider.GetAccessTokenAsync("https://vault.azure.net");

        // get the public certificate
        string pem;
        using (var client = new WebClient())
        {
            if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
            client.Headers.Add("Authorization", $"Bearer {accessToken}");
            string raw = client.DownloadString(new Uri($"https://researchandengineering.vault.azure.net/secrets/AUTH-PUB?api-version=7.0"));
            dynamic json = JObject.Parse(raw);
            pem = (string)json.value;
        }

        // get the body of the certificate as bytes
        var type = "CERTIFICATE";
        var header = $"-----BEGIN {type}-----";
        var start = pem.IndexOf(header, StringComparison.Ordinal);
        start += header.Length;
        var end = pem.IndexOf($"-----END {type}-----", start, StringComparison.Ordinal) - start;
        byte[] pub = Convert.FromBase64String(pem.Substring(start, end));

        // build the security key
        var certificate = new X509Certificate2(pub);
        SecurityKey key = new X509SecurityKey(certificate);

        // parameters to validate
        var handler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            RequireAudience = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuer = true,
            ValidIssuer = Issuer,
            ValidateAudience = true,
            ValidAudience = Audience,
            ValidateLifetime = true,
            IssuerSigningKey = key
        };

        // validate all previously defined parameters
        SecurityToken validatedSecurityToken = null;
        handler.ValidateToken(token, validationParameters, out validatedSecurityToken);
        JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;

        // write the output
        Console.WriteLine(validatedJwt.Payload.SerializeToJson());

    }

    public async Task GetUserFromGraph(string email)
    {

        // get a token for the graph
        var tokenProvider = new AzureServiceTokenProvider();
        string accessToken = await tokenProvider.GetAccessTokenAsync("https://graph.microsoft.com");

        // query for the user
        using (var client = new WebClient())
        {
            if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
            client.Headers.Add("Authorization", $"Bearer {accessToken}");
            string raw = client.DownloadString(new Uri($"https://graph.microsoft.com/beta/users?$filter=mail eq '{email}'"));
            dynamic json = JObject.Parse(raw);
            Console.WriteLine(json);
        }

    }

}