using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json; // System.Text.Json was not deserializing properly

namespace CasAuth
{

    public static class CasConfig
    {

        private class AppConfigItems
        {
            public AppConfigItem[] items = null;
        }

        private class AppConfigItem
        {
            public string content_type = null;
            public string key = null;
            public string value = null;
        }

        private class KeyVaultRef
        {
            public string uri = null;
        }

        public async static Task<Dictionary<string, string>> Load(HttpClient httpClient, string[] filters, bool useFullyQualifiedName = false)
        {

            // exit if there are no keys requested
            Dictionary<string, string> kv = new Dictionary<string, string>();
            if (filters.Length < 1) return kv;

            // get an accessToken
            string accessToken = await CasAuthChooser.GetAccessToken($"https://{CasEnv.AppConfig}", "AUTH_TYPE_CONFIG");

            // process each key filter request
            foreach (var filter in filters)
            {

                // make authenticated calls to Azure AppConfig
                using (var request = new HttpRequestMessage()
                {
                    RequestUri = new Uri($"https://{CasEnv.AppConfig}/kv?key={filter}"),
                    Method = HttpMethod.Get
                })
                {
                    request.Headers.Add("Authorization", $"Bearer {accessToken}");
                    using (var response = await httpClient.SendAsync(request))
                    {

                        // evaluate the response
                        var raw = await response.Content.ReadAsStringAsync();
                        if ((int)response.StatusCode == 401 || (int)response.StatusCode == 403)
                        {
                            throw new Exception($"CasConfig.Load: The identity is not authorized to get key/value pairs from the AppConfig: {CasEnv.AppConfig}; make sure this is the right instance and that you have granted rights to the Managed Identity or Service Principal. If running locally, make sure you have run an \"az login\" with the correct account and subscription.");
                        }
                        else if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"CasConfig.Load: HTTP {(int)response.StatusCode} - {raw}");
                        }

                        // look for key/value pairs
                        var json = JsonConvert.DeserializeObject<AppConfigItems>(raw);
                        foreach (var item in json.items)
                        {
                            var key = (useFullyQualifiedName) ? item.key : item.key.Split(":").Last();
                            key = key.ToUpper();
                            var val = item.value;
                            if (item.content_type.Contains("vnd.microsoft.appconfig.keyvaultref", StringComparison.InvariantCultureIgnoreCase))
                            {
                                val = JsonConvert.DeserializeObject<KeyVaultRef>(item.value).uri;
                            }
                            if (!kv.ContainsKey(key)) kv.Add(key, val);
                        }

                    };

                }
            }

            return kv;
        }

        public async static Task Apply(HttpClient httpClient, string[] filters = null)
        {

            // load the config
            if (filters == null) filters = CasEnv.ConfigKeys;
            Dictionary<string, string> kv = await CasConfig.Load(httpClient, filters);

            // apply the config
            foreach (var pair in kv)
            {
                System.Environment.SetEnvironmentVariable(pair.Key, pair.Value);
            }

        }

        private class KeyVaultItem
        {
            public string value = null;
        }

        public static async Task<string> GetFromKeyVault(HttpClient httpClient, string url, bool ignore404 = false)
        {

            // get an access token
            var accessToken = await CasAuthChooser.GetAccessToken("https://vault.azure.net", "AUTH_TYPE_VAULT");

            // get from the keyvault
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"{url}?api-version=7.0"),
                Method = HttpMethod.Get
            })
            {
                request.Headers.Add("Authorization", $"Bearer {accessToken}");
                using (var response = await httpClient.SendAsync(request))
                {
                    var raw = await response.Content.ReadAsStringAsync();
                    if (ignore404 && (int)response.StatusCode == 404) // Not Found
                    {
                        return string.Empty;
                    }
                    else if (!response.IsSuccessStatusCode)
                    {
                        throw new Exception($"CasTokenIssuer.GetFromKeyVault: HTTP {(int)response.StatusCode} - {raw}");
                    }
                    var item = JsonConvert.DeserializeObject<KeyVaultItem>(raw);
                    return item.value;
                }
            };

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

        public static bool Optional(string key, ILogger logger)
        {
            string value = System.Environment.GetEnvironmentVariable(key);
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

    }


}

