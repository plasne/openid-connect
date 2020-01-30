using System;
using System.Linq;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using System.Net.Http;
using System.Text;
using System.Security.Cryptography;
using System.Net.Http.Headers;
using System.IO;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json; // System.Text.Json was not deserializing properly

namespace CasAuth
{

    public class CasConfig
    {

        public static string AppConfigResourceId
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("APPCONFIG_RESOURCE_ID");
            }
        }

        public static string[] ParseFilterString(string compact)
        {
            if (string.IsNullOrEmpty(compact)) return new string[] { };
            return compact.Split(',').Select(id => id.Trim()).ToArray();
        }

        public static string[] ConfigKeys
        {
            get
            {
                return ParseFilterString(System.Environment.GetEnvironmentVariable("CONFIG_KEYS"));
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

        private class Keys
        {
            public Key[] value = null;
        }

        private class Key
        {
            public string id = null;
            public string value = null;
        }

        private async static Task<(string, string)> GetIdAndSecret(HttpClient httpClient)
        {
            string accessToken = await CasAuthChooser.GetAccessToken("https://management.azure.com", "AUTH_TYPE_CONFIG");
            string url = $"https://management.azure.com{AppConfigResourceId}/ListKeys?api-version=2019-10-01";
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri(url),
                Method = HttpMethod.Post
            })
            {
                request.Headers.Add("Authorization", $"Bearer {accessToken}");
                using (var response = await httpClient.SendAsync(request))
                {
                    var raw = await response.Content.ReadAsStringAsync();
                    if ((int)response.StatusCode == 401 || (int)response.StatusCode == 403)
                    {
                        throw new Exception($"CasConfig.GetIdAndSecret: The identity is not authorized to get management keys for the AppConfig: {AppConfigResourceId}; make sure this is the right instance and that you have granted rights to the Managed Identity or Service Principal. If running locally, make sure you have run an \"az login\" with the correct account and subscription.");
                    }
                    else if (!response.IsSuccessStatusCode)
                    {
                        throw new Exception($"CasConfig.GetIdAndSecret: HTTP {(int)response.StatusCode} - {raw}");
                    }
                    var keys = JsonConvert.DeserializeObject<Keys>(raw);
                    var pri = keys.value.First();
                    return ((string)pri.id, (string)pri.value);
                }
            };
        }

        private class Items
        {
            public Item[] items = null;
        }

        private class Item
        {
            public string key = null;
            public string value = null;
        }

        public async static Task<Dictionary<string, string>> Load(HttpClient httpClient, string[] filters, bool useFullyQualifiedName = false)
        {

            // exit if there are no keys requested
            Dictionary<string, string> kv = new Dictionary<string, string>();
            if (filters.Length < 1) return kv;

            // get the id and secret
            var (appConfigId, appConfigSecret) = await CasConfig.GetIdAndSecret(httpClient);

            // process each key filter request
            foreach (var filter in filters)
            {

                // config proxy if required
                var handler = new HttpClientHandler();
                if (!string.IsNullOrEmpty(CasEnv.Proxy)) handler.Proxy = new WebProxy(CasEnv.Proxy);

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
                    if (response.StatusCode == HttpStatusCode.Unauthorized) throw new Exception($"The identity is not authorized to get key/value pairs from the AppConfig: {AppConfigResourceId}; make sure this is the right instance and that you have granted rights to the Managed Identity or Service Principal. If running locally, make sure you have run an \"az login\" with the correct account and subscription.");
                    if (response.StatusCode != HttpStatusCode.OK) throw new Exception($"config could not be read from Azure AppConfig ({response.StatusCode}: {response.ReasonPhrase})");
                    var raw = await response.Content.ReadAsStringAsync();

                    // look for key/value pairs
                    var json = JsonConvert.DeserializeObject<Items>(raw);
                    foreach (var item in json.items)
                    {
                        var key = (useFullyQualifiedName) ? (string)item.key : ((string)item.key).Split(":").Last().ToUpper();
                        var val = (string)item.value;
                        if (!kv.ContainsKey(key)) kv.Add(key, val);
                    }

                }

            }

            return kv;
        }

        public async static Task Apply(HttpClient httpClient, string[] filters = null)
        {

            // load the config
            if (filters == null) filters = ConfigKeys;
            Dictionary<string, string> kv = await CasConfig.Load(httpClient, filters);

            // apply the config
            foreach (var pair in kv)
            {
                System.Environment.SetEnvironmentVariable(pair.Key, pair.Value);
            }

        }

        public static void Require(string key, string value, ILogger logger)
        {
            if (string.IsNullOrEmpty(value))
            {
                logger.LogError($"{key} is REQUIRED but missing.");
                throw new Exception($"{key} is REQUIRED but missing.");
            }
            else
            {
                logger.LogDebug($"{key} = \"{value}\"");
            }
        }

        public static void Require(string key, string[] values, ILogger logger)
        {
            if (values.Count(v => v.Trim().Length > 0) < 1)
            {
                logger.LogError($"{key} is REQUIRED but missing.");
                throw new Exception($"{key} is REQUIRED but missing.");
            }
            else
            {
                logger.LogDebug($"{key} = \"{string.Join(",", values)}\"");
            }
        }

        public static bool Optional(string key, string value, ILogger logger)
        {
            if (string.IsNullOrEmpty(value))
            {
                logger.LogDebug($"{key} is \"(not-set)\".");
                return false;
            }
            else
            {
                logger.LogDebug($"{key} = \"{value}\"");
                return true;
            }
        }

        public static bool Optional(string key, string[] values, ILogger logger)
        {
            if (values.Count(v => v.Trim().Length > 0) > 0)
            {
                logger.LogDebug($"{key} is \"(not-set)\".");
                return false;
            }
            else
            {
                logger.LogDebug($"{key} = \"{string.Join(";", values)}\"");
                return true;
            }
        }

        public static bool Optional(string key, bool value, ILogger logger)
        {
            logger.LogDebug($"{key} = \"{value.ToString()}\"");
            return true;
        }

    }


}

