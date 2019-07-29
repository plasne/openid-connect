using System;
using Microsoft.Identity.Client;
using dotenv.net;
using System.Threading.Tasks;
using System.Net;
using Newtonsoft.Json.Linq;

public class Graph
{

    public Graph()
    {
        DotEnv.Config();
    }

    private IConfidentialClientApplication App { get; set; }

    private async Task<bool> IsUserEnabled(string userId, string token)
    {
        return await Task.Run(() =>
        {
            using (var client = new WebClient())
            {
                client.Headers.Add("Authorization", $"Bearer {token}");
                string raw = client.DownloadString(new Uri($"https://graph.microsoft.com/beta/users/{userId}?$select=accountEnabled"));
                dynamic json = JObject.Parse(raw);
                return (bool)json.accountEnabled;
            }
        });
    }

    private async Task<bool> IsUserAuthorizedForApp(string userId, string token)
    {
        return await Task.Run(() =>
        {
            using (var client = new WebClient())
            {
                client.Headers.Add("Authorization", $"Bearer {token}");
                string raw = client.DownloadString(new Uri($"https://graph.microsoft.com/beta/users/{userId}/appRoleAssignments"));
                dynamic json = JObject.Parse(raw);
                var values = (JArray)json.value;
                string enterpriseAppId = authentication.Controllers.AuthController.EnterpriseAppId;
                foreach (dynamic value in values)
                {
                    var resourceId = (string)value.resourceId;
                    if (resourceId == enterpriseAppId) return true;
                }
            }
            return false;
        });
    }

    public async Task<bool> IsUserEnabledAndAuthorized(string userId)
    {

        // get the token
        string[] scopes = new string[] { "offline_access https://graph.microsoft.com/.default" };
        AuthenticationResult result = await this.App.AcquireTokenForClient(scopes).ExecuteAsync();

        // check all user requirements
        var t1 = IsUserEnabled(userId, result.AccessToken);
        var t2 = IsUserAuthorizedForApp(userId, result.AccessToken);
        await Task.WhenAll(t1, t2);
        Console.WriteLine($"user: {userId}, isEnabled? {t1.Result}, isAuthorized? {t2.Result}");

        return (t1.Result && t2.Result);
    }

    public void Start()
    {

        // build the app
        this.App = ConfidentialClientApplicationBuilder
            .Create(authentication.Controllers.AuthController.ClientId)
            .WithTenantId(authentication.Controllers.AuthController.TenantId)
            .WithClientSecret(authentication.Controllers.AuthController.ClientSecret)
            .Build();

    }

}