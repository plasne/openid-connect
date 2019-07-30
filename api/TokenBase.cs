using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using dotenv.net;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

public abstract class TokenBase
{

    public TokenBase()
    {

        // get the configuration
        DotEnv.Config();

        // create a builder to get permissions
        this.App = ConfidentialClientApplicationBuilder
            .Create(ClientId)
            .WithTenantId(TenantId)
            .WithClientSecret(ClientSecret)
            .Build();

    }

    protected IConfidentialClientApplication App { get; set; }

    public static string ClientId
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("CLIENT_ID");
        }
    }

    public static string ClientSecret
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("CLIENT_SECRET");
        }
    }

    public static string TenantId
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("TENANT_ID");
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

                // get an access token
                string[] scopes = new string[] { "offline_access https://vault.azure.net/.default" };
                var acquire = this.App.AcquireTokenForClient(scopes).ExecuteAsync();
                acquire.Wait();
                string token = acquire.Result.AccessToken;

                // get the certificate
                using (var client = new WebClient())
                {
                    client.Headers.Add("Authorization", $"Bearer {token}");
                    string raw = client.DownloadString(new Uri($"https://researchandengineering.vault.azure.net/secrets/AUTH-PUB?api-version=7.0"));
                    dynamic json = JObject.Parse(raw);
                    byte[] bytes = GetBytesFromPEM((string)json.value, "CERTIFICATE");
                    var certificate = new X509Certificate2(bytes);
                    _validationKey = new X509SecurityKey(certificate);
                }

            }
            return _validationKey;
        }
    }

}