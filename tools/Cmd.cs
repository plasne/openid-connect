using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using Newtonsoft.Json.Linq;
using System.Threading.Tasks;

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

    public void IssueToken(string oid, string displayName, string email, IEnumerable<string> roles)
    {

        // populate the claims
        List<Claim> claims = new List<Claim>();
        claims.Add(new Claim("oid", oid));
        claims.Add(new Claim("displayName", displayName));
        claims.Add(new Claim("email", email));
        if (!string.IsNullOrEmpty(Xsrf)) claims.Add(new Claim("xsrf", Xsrf));
        var oldOffset = new DateTimeOffset(DateTime.UtcNow).AddMinutes(JwtMaxDuration);
        claims.Add(new Claim("old", oldOffset.ToUnixTimeSeconds().ToString()));
        foreach (string role in roles)
        {
            claims.Add(new Claim("roles", role));
        }

        // generate the token
        var jwt = new JwtSecurityToken(
            issuer: Issuer,
            audience: Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(JwtDuration),
            signingCredentials: SigningCredentials);

        // write to string
        JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
        string jwt_s = handler.WriteToken(jwt);

        // write the output
        Console.WriteLine("");
        Console.WriteLine(jwt_s);
        Console.WriteLine("");
        Console.WriteLine(jwt.Payload.SerializeToJson());
        Console.WriteLine("");
        Console.WriteLine($"now: {DateTime.UtcNow}");
        Console.WriteLine($"from: {jwt.ValidFrom}");
        Console.WriteLine($"to: {jwt.ValidTo.ToUniversalTime()}");
        Console.WriteLine($"old: {oldOffset.ToUniversalTime()}");
        Console.WriteLine($"len: {jwt_s.Length}");

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

    public void ValidateToken(string token)
    {

        // get the signing keys
        var keys = ValidationCertificates.Select(c => new X509SecurityKey(c));

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
            IssuerSigningKeys = keys
        };

        // validate all previously defined parameters
        SecurityToken validatedSecurityToken = null;
        handler.ValidateToken(token, validationParameters, out validatedSecurityToken);
        JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;

        // write the output
        Console.WriteLine(validatedJwt.Payload.SerializeToJson());

    }

    public void GetCertificates()
    {
        foreach (var certificate in ValidationCertificates)
        {

            // get the parameters of the public key
            var pubkey = certificate.PublicKey.Key as dynamic;
            var parameters = pubkey.ExportParameters(false);

            // write out the info
            Console.WriteLine($"kid: {certificate.Thumbprint}");
            string x5t = Convert.ToBase64String(certificate.GetCertHash()).Replace("=", "");
            Console.WriteLine($"x5t: {x5t}");
            string n = Convert.ToBase64String(parameters.Modulus).Replace("=", "");
            Console.WriteLine($"n: {n}");
            string e = Convert.ToBase64String(parameters.Exponent);
            Console.WriteLine($"e: {e}");
            string x5c = Convert.ToBase64String(certificate.RawData);
            Console.WriteLine($"x5c: {x5c}");
            Console.WriteLine("");

        }
    }

    public async Task GetUserFromGraphByEmail(string email)
    {

        // get a token for the graph
        string accessToken = await AuthChooser.GetAccessToken("https://graph.microsoft.com");

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

    public async Task GetUserFromGraphByOid(string oid)
    {

        // get a token for the graph
        string accessToken = await AuthChooser.GetAccessToken("https://graph.microsoft.com");

        // query for the user
        using (var client = new WebClient())
        {
            if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
            client.Headers.Add("Authorization", $"Bearer {accessToken}");
            string raw = client.DownloadString(new Uri($"https://graph.microsoft.com/beta/users/{oid}"));
            dynamic json = JObject.Parse(raw);
            Console.WriteLine(json);
        }

    }

    public async Task GetAllConfig()
    {

        // get all config
        var kv = await Config.Load(new string[] { "*" }, useFullyQualifiedName: true);
        foreach (var pair in kv)
        {
            Console.WriteLine($"{pair.Key} = \"{pair.Value}\"");
        }

    }

}