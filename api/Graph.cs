using System;
using System.Linq;
using Microsoft.Identity.Client;
using dotenv.net;
using Microsoft.Graph;
using System.Threading.Tasks;

public class Graph
{

    public Graph()
    {
        DotEnv.Config();
    }

    private IConfidentialClientApplication App { get; set; }

    private string ClientId
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("CLIENT_ID");
        }
    }

    private string ClientSecret
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("CLIENT_SECRET");
        }
    }

    private string TenantId
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("TENANT_ID");
        }
    }

    public async Task<bool> IsUserEnabled(string id)
    {

        // get the token
        string[] scopes = new string[] { "offline_access https://graph.microsoft.com/.default" };
        AuthenticationResult result = await this.App.AcquireTokenForClient(scopes).ExecuteAsync();

        // get a graph client
        var graphServiceClient = new GraphServiceClient(new DelegateAuthenticationProvider((requestMessage) =>
                   {
                       requestMessage
                           .Headers
                           .Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("bearer", result.AccessToken);
                       return Task.FromResult(0);
                   }));

        // query for the specified user
        var users = await graphServiceClient
        .Users
        .Request()
        .Filter($"id eq '{id}'")
        .Select("displayName, accountEnabled")
        .GetAsync();

        foreach (var user in users)
        {
            Console.WriteLine($" user: {user.DisplayName} , enabled: {user.AccountEnabled}");
        }

        // return the appropiate value
        if (users.Count != 1) return false;
        return (bool)users.FirstOrDefault().AccountEnabled;

    }

    public void Start()
    {

        // build the app
        this.App = ConfidentialClientApplicationBuilder.Create(this.ClientId)
                   .WithTenantId(this.TenantId)
                   .WithClientSecret(this.ClientSecret)
                   .Build();

    }

}