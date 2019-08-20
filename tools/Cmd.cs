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
using System.Text.RegularExpressions;
using Newtonsoft.Json;

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

    private string GetStringFromUser(string prompt, Regex pattern, string error)
    {
        string value = null;
        do
        {
            Console.WriteLine(prompt);
            string response = Console.ReadLine();
            if (pattern == null || pattern.IsMatch(response))
            {
                value = response;
            }
            else
            {
                Console.WriteLine(error);
            }
        } while (string.IsNullOrEmpty(value));
        return value;
    }

    private bool GetBoolFromUser(string prompt)
    {
        string error = "Error: you must answer yes or no.";
        var positive = new string[] { "yes", "y", "1", "true" };
        var negative = new string[] { "no", "n", "0", "false" };
        while (true)
        {
            string response = GetStringFromUser(prompt, null, error).ToLower();
            if (positive.Contains(response)) return true;
            if (negative.Contains(response)) return false;
            Console.WriteLine(error);
        }
    }

    private int GetNumberFromUser(string prompt, int min, int max)
    {
        string error = $"Error: you must specify a number between {min} and {max}.";
        while (true)
        {
            string response = GetStringFromUser(prompt, new Regex("^[0-9]+$"), error).ToLower();
            if (int.TryParse(response, out int port))
            {
                if (port >= min && port <= max) return port;
            }
            Console.WriteLine(error);
        }
    }

    private string GetGuidFromUser(string prompt)
    {
        string error = "Error: you must specify a GUID.";
        while (true)
        {
            string response = GetStringFromUser(prompt, null, error).ToLower();
            if (Guid.TryParse(response, out Guid guid)) return guid.ToString();
            Console.WriteLine(error);
        }
    }

    private string GetUrlFromUser(string prompt)
    {
        string error = "Error: you must specify a valid, fully-qualified URL.";
        while (true)
        {
            string response = GetStringFromUser(prompt, null, error).ToLower();
            if (Uri.TryCreate(response, UriKind.Absolute, out Uri result)) return result.ToString();
            Console.WriteLine(error);
        }
    }

    public void RunConfigWizard()
    {

        // prelude
        Console.WriteLine("This wizard will create a JSON configuration file for \"dev\" and \"local\" environments.");

        // collect responses from the user
        Dictionary<string, string> config = new Dictionary<string, string>();
        string id = GetStringFromUser("[01/14] Please provide an identifier for your application (ex. sample)?",
            new Regex("^[a-zA-Z0-9-_]+$"),
            "Error: you may only use alphanumeric characters, dashes, or underscores.");
        string baseDomain = GetStringFromUser("[02/14] Please provide a base domain (ex. plasne.com)?",
            new Regex("^[a-zA-Z0-9-_.]+$"),
            "Error: you may only use alphanumeric characters, dashes, underscores, and periods.");
        string wfeSubDomain = GetStringFromUser("[03/14] Please provide a subdomain name for the WFE (ex. wfe)?",
            new Regex("^[a-zA-Z0-9-_]+$"),
            "Error: you may only use alphanumeric characters, dashes, and underscores.");
        string authSubDomain = GetStringFromUser("[04/14] Please provide a subdomain name for the auth service (ex. auth)?",
            new Regex("^[a-zA-Z0-9-_]+$"),
            "Error: you may only use alphanumeric characters, dashes, and underscores.");
        string apiSubDomain = GetStringFromUser("[05/14] Please provide a subdomain name for the API service (ex. api)?",
            new Regex("^[a-zA-Z0-9-_]+$"),
            "Error: you may only use alphanumeric characters, dashes, and underscores.");
        string tenantId = GetGuidFromUser("[06/14] What is the GUID of your Azure AD tenant that contains the authorization application?");
        string clientId = GetGuidFromUser("[07/14] What is the Application ID (also called Client ID) of the authorization application?");
        int duration = GetNumberFromUser("[08/14] How long (in minutes) do you want to sign the session_token for (ex. 240 minutes or 4 hours)?", 1, 60 * 24 * 30);
        string keyVault = GetStringFromUser("[09/14] What is the name of your Azure Key Vault - the name before .vault.azure.net (ex. plasne-keyvault)?",
            new Regex("^[a-zA-Z0-9-_]+$"),
            "Error: you may only use alphanumeric characters, dashes, or underscores.");
        bool allowReissue = GetBoolFromUser("[10/14] Do you want to allow tokens to be reissued (yes/no)?");
        int wfePort = GetNumberFromUser("[11/14] For local debugging, what port do you want to host your WFE on (ex. 5000)?", 1024, 65535);
        int authPort = GetNumberFromUser("[12/14] For local debugging, what port do you want to host your auth service on (ex. 5100)?", 1024, 65535);
        int apiPort = GetNumberFromUser("[13/14] For local debugging, what port do you want to host your API service on (ex. 5200)?", 1024, 65535);
        bool allowPermissiveDebug = GetBoolFromUser("[14/14] For local debugging, do you want to allow for a more permissive environment - ALLOW_TOKEN_IN_HEADER=true, VERIFY_XSRF_HEADER=false (yes/no)?");

        // build out the config
        config.Add($"{id}:auth:dev:AUTHORITY", "https://login.microsoftonline.com/{tenantId}");
        config.Add($"{id}:auth:dev:CLIENT_ID", clientId);
        config.Add($"{id}:auth:dev:DEFAULT_REDIRECT_URL", $"https://{wfeSubDomain}.{baseDomain}");
        config.Add($"{id}:auth:local:DEFAULT_REDIRECT_URL", $"http://localhost:{wfePort}");
        config.Add($"{id}:auth:dev:JWT_DURATION", duration.ToString());
        config.Add($"{id}:auth:dev:KEYVAULT_COMMAND_PASSWORD_URL", $"https://{keyVault}.vault.azure.net/secrets/COMMANDPW");
        config.Add($"{id}:auth:dev:KEYVAULT_PRIVATE_KEY_PASSWORD_URL", $"https://{keyVault}.vault.azure.net/secrets/PRIVATEKEYPW");
        config.Add($"{id}:auth:dev:KEYVAULT_PRIVATE_KEY_URL", $"https://{keyVault}.vault.azure.net/secrets/PRIVATEKEY");
        config.Add($"{id}:auth:dev:KEYVAULT_PUBLIC_CERT_PREFIX_URL", $"https://{keyVault}.vault.azure.net/secrets/PUBLIC-CERT-");
        config.Add($"{id}:auth:dev:PUBLIC_KEYS_URL", $"https://{authSubDomain}.{baseDomain}/api/auth/keys");
        config.Add($"{id}:auth:local:PUBLIC_KEYS_URL", $"http://localhost:{authPort}/api/auth/keys");
        config.Add($"{id}:auth:dev:REDIRECT_URI", $"https://{authSubDomain}.{baseDomain}/api/auth/token");
        config.Add($"{id}:auth:local:REDIRECT_URI", $"http://localhost:{authPort}/api/auth/token");
        config.Add($"{id}:api:dev:PRESENT_CONFIG_wfe", $"{id}:wfe:dev:*");
        config.Add($"{id}:api:local:PRESENT_CONFIG_wfe", $"{id}:wfe:local:*, {id}:wfe:dev:*");
        config.Add($"{id}:api:dev:WELL_KNOWN_CONFIG_URL", $"https://{authSubDomain}.{baseDomain}/api/auth/.well-known/openid-configuration");
        config.Add($"{id}:api:local:WELL_KNOWN_CONFIG_URL", $"http://localhost:{authPort}/api/auth/.well-known/openid-configuration");
        if (allowReissue)
        {
            config.Add($"{id}:api:dev:REISSUE_URL", $"https://{authSubDomain}.{baseDomain}/api/auth/reissue");
            config.Add($"{id}:api:local:REISSUE_URL", $"http://localhost:{authPort}/api/auth/reissue");
        }
        if (allowPermissiveDebug)
        {
            config.Add($"{id}:api:local:ALLOW_TOKEN_IN_HEADER", "true");
            config.Add($"{id}:api:local:VERIFY_XSRF_HEADER", "false");
        }
        config.Add($"{id}:common:dev:ALLOWED_ORIGINS", $"https://{wfeSubDomain}.{baseDomain}");
        config.Add($"{id}:common:local:ALLOWED_ORIGINS", $"http://localhost:{wfePort}");
        config.Add($"{id}:common:dev:AUDIENCE", $"https://{apiSubDomain}.{baseDomain}");
        config.Add($"{id}:common:dev:ISSUER", $"https://{authSubDomain}.{baseDomain}");
        config.Add($"{id}:common:dev:BASE_DOMAIN", baseDomain);
        config.Add($"{id}:common:local:BASE_DOMAIN", "localhost");
        config.Add($"{id}:wfe:dev:LOGIN_URL", $"https://{authSubDomain}.{baseDomain}/api/auth/authorize");
        config.Add($"{id}:wfe:local:LOGIN_URL", $"http://localhost:{authPort}/api/auth/authorize");
        config.Add($"{id}:wfe:dev:ME_URL", $"https://{apiSubDomain}.{baseDomain}/api/identity/me");
        config.Add($"{id}:wfe:local:ME_URL", $"http://localhost:{apiPort}/api/identity/me");

        // write out the config
        string stringified = JsonConvert.SerializeObject(config, Formatting.Indented);
        Console.WriteLine("");
        Console.WriteLine(stringified);
        Console.WriteLine("");
        Console.WriteLine("Written to config.json.");
        System.IO.File.WriteAllText("./config.json", stringified);

    }

}