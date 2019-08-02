using System;
using System.Linq;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.Net.Http;
using System.Text;
using System.Security.Cryptography;
using System.Net.Http.Headers;
using System.IO;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Logging;

public class Config
{

    public static string Proxy
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("PROXY");
        }
    }

    private static string KeyVaultAppConfigPrefixUrl
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("KEYVAULT_APPCONFIG_PREFIX_URL");
        }
    }

    private static string[] ConfigKeys
    {
        get
        {
            return ParseFilterString(System.Environment.GetEnvironmentVariable("CONFIG_KEYS"));
        }
    }

    public static string[] ParseFilterString(string compact)
    {
        if (string.IsNullOrEmpty(compact)) return new string[] { };
        return compact.Split(',').Select(id => id.Trim()).ToArray();
    }

    private static void Sign(HttpRequestMessage request, string credential, byte[] secret)
    {
        // from: https://github.com/Azure/AppConfiguration/blob/master/docs/REST/authentication.md
        string host = request.RequestUri.Authority;
        string verb = request.Method.ToString().ToUpper();
        DateTimeOffset utcNow = DateTimeOffset.UtcNow;
        string contentHash = Convert.ToBase64String(ComputeSha256Hash(request.Content));

        // sign
        string signedHeaders = "date;host;x-ms-content-sha256"; // Semicolon separated header names
        var stringToSign = $"{verb}\n{request.RequestUri.PathAndQuery}\n{utcNow.ToString("r")};{host};{contentHash}";
        string signature;
        using (var hmac = new HMACSHA256(secret))
        {
            signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.ASCII.GetBytes(stringToSign)));
        }

        // add headers
        request.Headers.Date = utcNow;
        request.Headers.Add("x-ms-content-sha256", contentHash);
        request.Headers.Authorization = new AuthenticationHeaderValue("HMAC-SHA256", $"Credential={credential}, SignedHeaders={signedHeaders}, Signature={signature}");

    }

    private static byte[] ComputeSha256Hash(HttpContent content)
    {
        // from: https://github.com/Azure/AppConfiguration/blob/master/docs/REST/authentication.md
        using (var stream = new MemoryStream())
        {
            if (content != null)
            {
                content.CopyToAsync(stream).Wait();
                stream.Seek(0, SeekOrigin.Begin);
            }
            using (var alg = SHA256.Create())
            {
                return alg.ComputeHash(stream.ToArray());
            }
        }
    }

    public async static Task<Dictionary<string, string>> Load(string[] filters, ILoggerFactory factory = null)
    {
        Dictionary<string, string> kv = new Dictionary<string, string>();

        // check environment variables
        if (string.IsNullOrEmpty("APPCONFIG_ID")) throw new Exception("missing required APPCONFIG_ID");
        if (string.IsNullOrEmpty("APPCONFIG_SECRET")) throw new Exception("missing required APPCONFIG_SECRET");
        if (string.IsNullOrEmpty("CONFIG_KEYS")) throw new Exception("missing required CONFIG_KEYS");

        // exit if there are no keys requested
        if (ConfigKeys.Length < 1) return kv;

        // create a logger
        ILogger logger = (factory != null) ? factory.CreateLogger<Config>() : null;

        // get a token
        var tokenProvider = new AzureServiceTokenProvider();
        var accessToken = await tokenProvider.GetAccessTokenAsync("https://vault.azure.net").ConfigureAwait(false);

        // get the APPCONFIG-ID
        string AppConfigId;
        using (var client = new WebClient())
        {
            if (!string.IsNullOrEmpty(Proxy)) client.Proxy = new WebProxy(Proxy);
            client.Headers.Add("Authorization", $"Bearer {accessToken}");
            string raw = client.DownloadString(new Uri($"{KeyVaultAppConfigPrefixUrl}ID?api-version=7.0"));
            dynamic json = JObject.Parse(raw);
            AppConfigId = (string)json.value;
        }

        // get the APPCONFIG-SECRET
        string AppConfigSecret;
        using (var client = new WebClient())
        {
            if (!string.IsNullOrEmpty(Proxy)) client.Proxy = new WebProxy(Proxy);
            client.Headers.Add("Authorization", $"Bearer {accessToken}");
            string raw = client.DownloadString(new Uri($"{KeyVaultAppConfigPrefixUrl}SECRET?api-version=7.0"));
            dynamic json = JObject.Parse(raw);
            AppConfigSecret = (string)json.value;
        }

        // process each key filter request
        foreach (var filter in filters)
        {

            // config proxy if required
            var handler = new HttpClientHandler();
            if (!string.IsNullOrEmpty(Proxy)) handler.Proxy = new WebProxy(Proxy);

            // make authenticated calls to Azure AppConfig
            using (var client = new HttpClient(handler))
            {

                // create the request message
                var request = new HttpRequestMessage()
                {
                    RequestUri = new Uri($"https://pelasne-config.azconfig.io/kv?key={filter}"),
                    Method = HttpMethod.Get
                };

                // sign the message
                Sign(request, AppConfigId, Convert.FromBase64String(AppConfigSecret));

                // get the response
                var response = await client.SendAsync(request);
                if (response.StatusCode != HttpStatusCode.OK) throw new Exception("config could not be read from Azure AppConfig");
                var raw = await response.Content.ReadAsStringAsync();

                // look for key/value pairs
                dynamic json = JObject.Parse(raw);
                foreach (dynamic item in json.items)
                {
                    var key = ((string)item.key).Split(":").Last().ToUpper();
                    var val = (string)item.value;
                    kv[key] = val;
                }

            }

        }

        return kv;
    }

    public async static Task Apply(string[] filters = null, ILoggerFactory factory = null)
    {

        // create a logger
        ILogger logger = (factory != null) ? factory.CreateLogger<Config>() : null;

        // load the config
        if (filters == null) filters = ConfigKeys;
        Dictionary<string, string> kv = await Config.Load(filters, factory);

        // apply the config
        foreach (var pair in kv)
        {
            var cur = System.Environment.GetEnvironmentVariable(pair.Key);
            if (string.IsNullOrEmpty(cur))
            {
                System.Environment.SetEnvironmentVariable(pair.Key, pair.Value);
                if (logger != null)
                {
                    logger.LogDebug($"config: {pair.Key} = \"{pair.Value}\"");
                }
                else
                {
                    Console.WriteLine($"config: {pair.Key} = \"{pair.Value}\"");
                }
            }
            else
            {
                if (logger != null)
                {
                    logger.LogDebug($"config: [already set] {pair.Key} = \"{pair.Value}\"");
                }
                else
                {
                    Console.WriteLine($"config: [already set] {pair.Key} = \"{pair.Value}\"");
                }
            }
        }

    }

    public static void Require(IEnumerable<string> keys)
    {

        // verify that all required parameters are provided or don't start up
        foreach (var key in keys)
        {
            if (string.IsNullOrEmpty(System.Environment.GetEnvironmentVariable(key)))
            {
                throw new Exception($"config: missing required parameter \"{key}\"");
            }
        }

    }

}