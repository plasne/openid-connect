using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Identity.Client;

namespace CasAuth
{

    public class CasAuthChooser
    {

        public static string AuthType(string key = "AUTH_TYPE")
        {
            string type = System.Environment.GetEnvironmentVariable(key);
            if (string.IsNullOrEmpty(type) && key != "AUTH_TYPE") type = System.Environment.GetEnvironmentVariable("AUTH_TYPE");
            if (string.IsNullOrEmpty(type)) return "mi";
            string[] app = new string[] { "app", "application", "service", "service_principal", "service-principal", "service principal" };
            return (app.Contains(type.ToLower())) ? "app" : "mi";
        }

        public static async Task<string> GetAccessTokenByApplication(string resourceId, string tenantId, string clientId, string clientSecret)
        {

            // builder
            var app = ConfidentialClientApplicationBuilder
                .Create(clientId)
                .WithTenantId(tenantId)
                .WithClientSecret(clientSecret)
                .Build();

            // ensure resourceId does not have trailing /
            if (resourceId.Last() == '/') resourceId.Substring(0, resourceId.Length - 1);

            // get an access token
            string[] scopes = new string[] { $"offline_access {resourceId}/.default" };
            var acquire = await app.AcquireTokenForClient(scopes).ExecuteAsync();
            return acquire.AccessToken;

        }

        public static async Task<string> GetAccessTokenByManagedIdentity(string resourceId)
        {
            var tokenProvider = new AzureServiceTokenProvider();
            return await tokenProvider.GetAccessTokenAsync(resourceId);
        }

        public static async Task<string> GetAccessToken(string resourceId, string authTypeKey, ICasConfig config = null)
        {
            switch (AuthType(authTypeKey))
            {
                case "app":
                    switch (authTypeKey)
                    {
                        case "AUTH_TYPE_CONFIG":
                            return await GetAccessTokenByApplication(resourceId, CasEnv.TenantIdConfig, CasEnv.ClientIdConfig, CasEnv.ClientSecretConfig);
                        case "AUTH_TYPE_GRAPH":
                            if (config == null) throw new Exception("config must be supplied for AUTH_TYPE_GRAPH");
                            var graphSecret = await config.GetString("CLIENT_SECRET_GRAPH", CasEnv.ClientSecretGraph);
                            return await GetAccessTokenByApplication(resourceId, CasEnv.TenantIdGraph, CasEnv.ClientIdGraph, graphSecret);
                        case "AUTH_TYPE_VAULT":
                            return await GetAccessTokenByApplication(resourceId, CasEnv.TenantIdVault, CasEnv.ClientIdVault, CasEnv.ClientSecretVault);
                        default:
                            throw new Exception("GetAccessToken requires an authTypeKey when using AUTH_TYPE=app");
                    }
                default:
                    return await GetAccessTokenByManagedIdentity(resourceId);
            }
        }

    }

}