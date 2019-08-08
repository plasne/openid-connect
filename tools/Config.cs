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

    private static string AppConfigResourceId
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("APPCONFIG_RESOURCE_ID");
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

    public async static Task<Dictionary<string, string>> Load(string[] filters, ILoggerFactory factory = null, bool useFullyQualifiedName = false)
    {

        // exit if there are no keys requested
        Dictionary<string, string> kv = new Dictionary<string, string>();
        if (filters.Length < 1) return kv;

        // create a logger
        ILogger logger = (factory != null) ? factory.CreateLogger<Config>() : null;

        // get a token
        string accessToken = await AuthChooser.GetAccessToken("https://management.azure.com");

        // get the id and secret
        string appConfigId, appConfigSecret;
        using (var client = new WebClient())
        {
            if (!string.IsNullOrEmpty(Proxy)) client.Proxy = new WebProxy(Proxy);
            client.Headers.Add("Authorization", $"Bearer {accessToken}");
            string url = $"https://management.azure.com{AppConfigResourceId}/ListKeys?api-version=2019-02-01-preview";
            byte[] bytes = client.UploadData(new Uri(url), Encoding.UTF8.GetBytes(string.Empty));
            string raw = Encoding.UTF8.GetString(bytes);
            dynamic json = JObject.Parse(raw);
            JArray values = json.value;
            dynamic pri = values.First();
            appConfigId = (string)pri.id;
            appConfigSecret = (string)pri.value;
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
                string appConfigName = AppConfigResourceId.Split("/").Last();
                var request = new HttpRequestMessage()
                {
                    RequestUri = new Uri($"https://{appConfigName}.azconfig.io/kv?key={filter}"),
                    Method = HttpMethod.Get
                };

                // sign the message
                Sign(request, appConfigId, Convert.FromBase64String(appConfigSecret));

                // get the response
                var response = await client.SendAsync(request);
                if (response.StatusCode != HttpStatusCode.OK) throw new Exception("config could not be read from Azure AppConfig");
                var raw = await response.Content.ReadAsStringAsync();

                // look for key/value pairs
                dynamic json = JObject.Parse(raw);
                foreach (dynamic item in json.items)
                {
                    var key = (useFullyQualifiedName) ? (string)item.key : ((string)item.key).Split(":").Last().ToUpper();
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

    public static void Optional(IEnumerable<string> keys)
    {
        // this is just designed to clearly show the options, it doesn't do anything
    }

}