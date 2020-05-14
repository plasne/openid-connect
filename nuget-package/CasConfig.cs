using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json; // System.Text.Json was not deserializing properly

namespace CasAuth
{

    public class CasConfig : ICasConfig
    {

        public CasConfig(ILogger<CasConfig> logger = null, HttpClient httpClient = null, IHttpClientFactory httpClientFactory = null)
        {
            this.Logger = logger;
            this.HttpClient = httpClient ?? httpClientFactory?.CreateClient("cas");
        }

        private ILogger<CasConfig> Logger { get; }
        private HttpClient HttpClient { get; }
        private string[] Positive { get; } = new string[] { "true", "1", "yes" };
        private string[] Negative { get; } = new string[] { "false", "0", "no" };
        public Dictionary<string, object> Cache { get; } = new Dictionary<string, object>();

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

        public async Task<Dictionary<string, string>> Load(string[] filters, bool useFullyQualifiedName = false)
        {

            // exit if there is nothing requested or no way to get it
            Dictionary<string, string> kv = new Dictionary<string, string>();
            if (string.IsNullOrEmpty(CasEnv.AppConfig)) return kv;
            if (filters.Length < 1) return kv;
            if (this.HttpClient == null) throw new Exception("APP_CONFIG and CONFIG_KEYS is provided, but a valid HttpClient was not.");

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
                    using (var response = await this.HttpClient.SendAsync(request))
                    {

                        // evaluate the response
                        var raw = await response.Content.ReadAsStringAsync();
                        if ((int)response.StatusCode == 401 || (int)response.StatusCode == 403)
                        {
                            throw new Exception($"Config.Load: The identity is not authorized to get key/value pairs from the AppConfig: {CasEnv.AppConfig}; make sure this is the right instance and that you have granted rights to the Managed Identity or Service Principal. If running locally, make sure you have run an \"az login\" with the correct account and subscription.");
                        }
                        else if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"Config.Load: HTTP {(int)response.StatusCode} - {raw}");
                        }

                        // look for key/value pairs
                        var json = JsonConvert.DeserializeObject<AppConfigItems>(raw);
                        foreach (var item in json.items)
                        {
                            Logger.LogDebug($"Config.Load: loaded \"{item.key}\" = \"{item.value}\".");
                            var key = (useFullyQualifiedName) ? item.key : item.key.Split(":").Last();
                            key = key.ToUpper();
                            var val = item.value;
                            if (item.content_type != null && item.content_type.Contains("vnd.microsoft.appconfig.keyvaultref", StringComparison.InvariantCultureIgnoreCase))
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

        public async Task Apply(string[] filters = null)
        {

            // load the config
            if (filters == null) filters = CasEnv.ConfigKeys;
            Dictionary<string, string> kv = await Load(filters);

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

        private async Task<string> GetFromKeyVault(string posurl, bool ignore404 = false)
        {
            if (
                !string.IsNullOrEmpty(posurl) &&
                posurl.StartsWith("https://", StringComparison.InvariantCultureIgnoreCase) &&
                posurl.Contains(".vault.azure.net/", StringComparison.InvariantCultureIgnoreCase)
            )
            {

                // get an access token
                var accessToken = await CasAuthChooser.GetAccessToken("https://vault.azure.net", "AUTH_TYPE_VAULT");

                // get from the keyvault
                using (var request = new HttpRequestMessage()
                {
                    RequestUri = new Uri($"{posurl}?api-version=7.0"),
                    Method = HttpMethod.Get
                })
                {
                    request.Headers.Add("Authorization", $"Bearer {accessToken}");
                    using (var response = await this.HttpClient.SendAsync(request))
                    {
                        var raw = await response.Content.ReadAsStringAsync();
                        if (ignore404 && (int)response.StatusCode == 404) // Not Found
                        {
                            return string.Empty;
                        }
                        else if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"Config.GetFromKeyVault: HTTP {(int)response.StatusCode} - {raw}");
                        }
                        var item = JsonConvert.DeserializeObject<KeyVaultItem>(raw);
                        return item.value;
                    }
                };

            }
            else
            {
                return posurl;
            }
        }

        public static async Task<string> GetStringOnce(string key, Func<Task<string>> dflt)
        {
            string val = System.Environment.GetEnvironmentVariable(key);
            if (string.IsNullOrEmpty(val)) val = await dflt();
            return val;
        }

        public static string GetStringOnce(string key, Func<string> dflt)
        {
            string val = System.Environment.GetEnvironmentVariable(key);
            if (string.IsNullOrEmpty(val)) val = dflt();
            return val;
        }

        public static string GetStringOnce(string key, string dflt = null)
        {
            return GetStringOnce(key, () => dflt);
        }

        public async Task<string> GetString(string key, string val, string dflt = null)
        {
            if (Cache.ContainsKey(key))
            {
                return (string)Cache[key];
            }
            else
            {
                val = string.IsNullOrEmpty(val) ? System.Environment.GetEnvironmentVariable(key) : val;
                val = await GetFromKeyVault(val);
                if (string.IsNullOrEmpty(val)) val = dflt;
                Cache.Add(key, val);
                return val;
            }
        }

        public static async Task<int> GetIntOnce(string key, Func<Task<int>> dflt)
        {
            string val = System.Environment.GetEnvironmentVariable(key);
            int ival;
            // bugfix: oddly TryParse sets ival to default(T) not keeping dflt
            if (!int.TryParse(val, out ival)) ival = await dflt();
            return ival;
        }

        public static int GetIntOnce(string key, Func<int> dflt)
        {
            string val = System.Environment.GetEnvironmentVariable(key);
            int ival;
            // bugfix: oddly TryParse sets ival to default(T) not keeping dflt
            if (!int.TryParse(val, out ival)) ival = dflt();
            return ival;
        }

        public static int GetIntOnce(string key, int dflt = 0)
        {
            return GetIntOnce(key, () => dflt);
        }

        public async Task<int> GetInt(string key, string val = null, int dflt = 0)
        {
            if (Cache.ContainsKey(key))
            {
                return (int)Cache[key];
            }
            else
            {
                val = string.IsNullOrEmpty(val) ? System.Environment.GetEnvironmentVariable(key) : val;
                val = await GetFromKeyVault(val);
                int ival = dflt;
                // bugfix: oddly TryParse sets ival to default(T) not keeping dflt
                if (!int.TryParse(val, out ival)) ival = dflt;
                Cache.Add(key, ival);
                return ival;
            }
        }

        public static bool GetBoolOnce(string key, Func<bool> dflt)
        {
            string val = System.Environment.GetEnvironmentVariable(key);
            if (new string[] { "true", "1", "yes" }.Contains(val?.ToLower())) return true;
            if (new string[] { "false", "0", "no" }.Contains(val?.ToLower())) return false;
            return dflt();
        }

        public static bool GetBoolOnce(string key, bool dflt = false)
        {
            return GetBoolOnce(key, () => dflt);
        }

        public async Task<bool> GetBool(string key, string val = null, bool dflt = false)
        {
            if (Cache.ContainsKey(key))
            {
                return (bool)Cache[key];
            }
            else
            {
                val = string.IsNullOrEmpty(val) ? System.Environment.GetEnvironmentVariable(key) : val;
                val = await GetFromKeyVault(val);
                if (Positive.Contains(val?.ToLower())) return true;
                if (Negative.Contains(val?.ToLower())) return false;
                bool bval = dflt;
                Cache.Add(key, bval);
                return bval;
            }
        }

        public static async Task<string[]> GetArrayOnce(string key, string delimiter, Func<Task<string[]>> dflt)
        {
            string val = System.Environment.GetEnvironmentVariable(key);
            if (!string.IsNullOrEmpty(val)) return val.Split(delimiter).Select(id => id.Trim()).ToArray();
            return await dflt();
        }

        public static string[] GetArrayOnce(string key, string delimiter, Func<string[]> dflt)
        {
            string val = System.Environment.GetEnvironmentVariable(key);
            if (!string.IsNullOrEmpty(val)) return val.Split(delimiter).Select(id => id.Trim()).ToArray();
            return dflt();
        }

        public static string[] GetArrayOnce(string key, string delimiter = ",", string[] dflt = null)
        {
            return GetArrayOnce(key, delimiter, () => dflt ?? new string[] { });
        }

        public async Task<string[]> GetArray(string key, string val = null, string delimiter = ",", string[] dflt = null)
        {
            if (Cache.ContainsKey(key))
            {
                return (string[])Cache[key];
            }
            else
            {
                val = string.IsNullOrEmpty(val) ? System.Environment.GetEnvironmentVariable(key) : val;
                val = await GetFromKeyVault(val);
                var aval = dflt ?? new string[] { };
                if (!string.IsNullOrEmpty(val)) aval = val.Split(delimiter).Select(id => id.Trim()).ToArray();
                Cache.Add(key, aval);
                return aval;
            }
        }

        public static async Task<T> GetEnumOnce<T>(string key, Func<Task<T>> dflt) where T : struct
        {
            string val = System.Environment.GetEnvironmentVariable(key);
            T tval;
            // bugfix: oddly TryParse sets tval to default(T) not keeping dflt
            if (!Enum.TryParse(val, true, out tval)) tval = await dflt();
            return tval;
        }

        public static T GetEnumOnce<T>(string key, Func<T> dflt) where T : struct
        {
            string val = System.Environment.GetEnvironmentVariable(key);
            T tval;
            // bugfix: oddly TryParse sets tval to default(T) not keeping dflt
            if (!Enum.TryParse(val, true, out tval)) tval = dflt();
            return tval;
        }

        public static T GetEnumOnce<T>(string key, T dflt = default(T)) where T : struct
        {
            return GetEnumOnce<T>(key, () => dflt);
        }

        public async Task<T> GetEnum<T>(string key, string val = null, T dflt = default(T)) where T : struct
        {
            if (Cache.ContainsKey(key))
            {
                return (T)Cache[key];
            }
            else
            {
                val = string.IsNullOrEmpty(val) ? System.Environment.GetEnvironmentVariable(key) : val;
                val = await GetFromKeyVault(val);
                T tval = dflt;
                // bugfix: oddly TryParse sets tval to default(T) not keeping dflt
                if (!Enum.TryParse(val, true, out tval)) tval = dflt;
                Cache.Add(key, tval);
                return tval;
            }
        }

        public void Require(string key, string value, bool hideValue = false)
        {
            if (string.IsNullOrEmpty(value))
            {
                this.Logger.LogError($"{key} is REQUIRED but missing.");
                throw new Exception($"{key} is REQUIRED but missing.");
            }
            else
            {
                this.Logger.LogDebug($"{key} = \"{(!hideValue ? value : "(set)")}\"");
            }
        }

        public void Require(string key, string[] values, bool hideValue = false)
        {
            if (values.Count(v => v.Trim().Length > 0) < 1)
            {
                this.Logger.LogError($"{key} is REQUIRED but missing.");
                throw new Exception($"{key} is REQUIRED but missing.");
            }
            else
            {
                this.Logger.LogDebug($"{key} = \"{(!hideValue ? string.Join(",", values) : "(set)")}\"");
            }
        }

        public void Require(string key, bool hideValue = false)
        {
            string value = System.Environment.GetEnvironmentVariable(key);
            Require(key, value, hideValue);
        }

        public bool Optional(string key, string value, bool hideValue = false, bool hideIfEmpty = false)
        {
            if (string.IsNullOrEmpty(value))
            {
                if (!hideIfEmpty) this.Logger.LogDebug($"{key} is \"(not-set)\".");
                return false;
            }
            else
            {
                this.Logger.LogDebug($"{key} = \"{(!hideValue ? value : "(set)")}\"");
                return true;
            }
        }

        public bool Optional(string key, string[] values, bool hideValue = false, bool hideIfEmpty = false)
        {
            if (values == null || values.Count(v => v.Trim().Length > 0) < 1)
            {
                if (!hideIfEmpty) this.Logger.LogDebug($"{key} is \"(not-set)\".");
                return false;
            }
            else
            {
                this.Logger.LogDebug($"{key} = \"{(!hideValue ? string.Join(", ", values) : "(set)")}\"");
                return true;
            }
        }

        public bool Optional(string key, bool value, bool hideValue = false, bool hideIfEmpty = false)
        {
            this.Logger.LogDebug($"{key} = \"{(!hideValue ? value.ToString() : "(set)")}\"");
            return true;
        }

        public bool Optional(string key, bool hideValue = false, bool hideIfEmpty = false)
        {
            string value = System.Environment.GetEnvironmentVariable(key);
            if (string.IsNullOrEmpty(value))
            {
                if (!hideIfEmpty) this.Logger.LogDebug($"{key} is \"(not-set)\".");
                return false;
            }
            else
            {
                this.Logger.LogDebug($"{key} = \"{(!hideValue ? value : "(set)")}\"");
                return true;
            }
        }

    }


}

