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
            string keys = System.Environment.GetEnvironmentVariable("CONFIG_KEYS");
            if (string.IsNullOrEmpty(keys)) return new string[] { };
            return keys.Split(',').Select(id => id.Trim()).ToArray();
        }
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

    public async static Task Load(ILoggerFactory factory = null)
    {

        // check environment variables
        if (string.IsNullOrEmpty("APPCONFIG_ID")) throw new Exception("missing required APPCONFIG_ID");
        if (string.IsNullOrEmpty("APPCONFIG_SECRET")) throw new Exception("missing required APPCONFIG_SECRET");
        if (string.IsNullOrEmpty("CONFIG_KEYS")) throw new Exception("missing required CONFIG_KEYS");

        // exit if there are no keys requested
        if (ConfigKeys.Length < 1) return;

        // create a logger
        ILogger logger = (factory != null) ? factory.CreateLogger<Config>() : null;

        // get a token
        var tokenProvider = new AzureServiceTokenProvider();
        var accessToken = await tokenProvider.GetAccessTokenAsync("https://vault.azure.net").ConfigureAwait(false);

        // get the APPCONFIG-ID
        string AppConfigId;
        using (var client = new WebClient())
        {
            client.Headers.Add("Authorization", $"Bearer {accessToken}");
            string raw = client.DownloadString(new Uri($"{KeyVaultAppConfigPrefixUrl}ID?api-version=7.0"));
            dynamic json = JObject.Parse(raw);
            AppConfigId = (string)json.value;
        }

        // get the APPCONFIG-SECRET
        string AppConfigSecret;
        using (var client = new WebClient())
        {
            client.Headers.Add("Authorization", $"Bearer {accessToken}");
            string raw = client.DownloadString(new Uri($"{KeyVaultAppConfigPrefixUrl}SECRET?api-version=7.0"));
            dynamic json = JObject.Parse(raw);
            AppConfigSecret = (string)json.value;
        }

        // process each key filter request
        foreach (var filter in ConfigKeys)
        {
            using (var client = new HttpClient())
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
                    if (string.IsNullOrEmpty(System.Environment.GetEnvironmentVariable(key)))
                    {
                        System.Environment.SetEnvironmentVariable(key, val);
                        if (logger != null)
                        {
                            logger.LogDebug($"config: {key} = \"{val}\"");
                        }
                        else
                        {
                            Console.WriteLine($"config: {key} = \"{val}\"");
                        }
                    }
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