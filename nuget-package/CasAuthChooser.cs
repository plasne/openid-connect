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

        public static async Task<string> GetAccessTokenByApplication(string resourceId)
        {

            // builder
            var app = ConfidentialClientApplicationBuilder
                .Create(CasEnv.ClientId)
                .WithTenantId(CasEnv.TenantId)
                .WithClientSecret(CasEnv.ClientSecret)
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

        public static Task<string> GetAccessToken(string resourceId, string authTypeKey)
        {
            if (AuthType(authTypeKey) == "app") return GetAccessTokenByApplication(resourceId);
            return GetAccessTokenByManagedIdentity(resourceId);
        }

    }

}