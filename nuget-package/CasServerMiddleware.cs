using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http;
using Newtonsoft.Json;

namespace CasAuth
{

    public class CasServerAuthMiddleware
    {
        // used just for ILogger
    }

    public static class UseCasServerAuthMiddlewareExtensions
    {

        public class WellKnownConfigPayload
        {
            public string issuer { get; set; }
            public string jwks_uri { get; set; }
        }

        public class Key
        {
            public string kty { get { return "RSA"; } }
            public string use { get { return "sig"; } }
            public string kid { get; set; }
            public string x5t { get; set; }
            public string n { get; set; }
            public string e { get; set; }
            public List<string> x5c { get; set; } = new List<string>();

            public Key(X509Certificate2 certificate)
            {

                // get the parameters of the public key
                var pubkey = certificate.PublicKey.Key as dynamic;
                var parameters = pubkey.ExportParameters(false);

                // populate the info
                kid = certificate.Thumbprint;
                x5t = Convert.ToBase64String(certificate.GetCertHash()).Replace("=", "");
                n = Convert.ToBase64String(parameters.Modulus).Replace("=", "");
                e = Convert.ToBase64String(parameters.Exponent);
                x5c.Add(Convert.ToBase64String(certificate.RawData));

            }
        }

        public class KeysPayload
        {
            public List<Key> keys { get; set; } = new List<Key>();
        }

        public static IApplicationBuilder UseCasServerAuth(this IApplicationBuilder builder)
        {

            // define additional endpoints
            builder.UseEndpoints(endpoints =>
            {

                // define options preflight
                endpoints.MapMethods("/cas/{**all}", new string[] { "OPTIONS" }, context =>
                {
                    context.Response.StatusCode = 204;
                    return context.Response.CompleteAsync();
                }).RequireCors("cas-server");

                // define the authorize endpoint
                endpoints.MapGet("/cas/authorize", async context =>
                {
                    try
                    {

                        // hand off to the idp
                        string idp = context.Request.Query["idp"];
                        if (string.IsNullOrEmpty(idp)) idp = "azure";
                        var providers = context.RequestServices.GetServices<ICasIdp>();
                        var provider = providers.FirstOrDefault(i => string.Compare(i.Id, idp, StringComparison.InvariantCultureIgnoreCase) == 0);
                        if (provider == null) throw new CasHttpException(400, $"\"{idp}\" was not a supported authentication provider.");
                        await provider.Authorize(context);

                    }
                    catch (Exception e)
                    {
                        await e.Apply(context);
                    }
                }).RequireCors("cas-server");

                // define the token endpoints
                endpoints.MapPost("/cas/token", async context =>
                {
                    try
                    {

                        // read flow to get the IDP
                        if (!context.Request.Cookies.ContainsKey("authflow")) throw new CasHttpException(400, "authflow not provided");
                        var flow = JsonConvert.DeserializeObject<CasAuthFlow>(context.Request.Cookies["authflow"]);

                        // hand off to the IDP
                        var providers = context.RequestServices.GetServices<ICasIdp>();
                        var provider = providers.FirstOrDefault(i => string.Compare(i.Id, flow.idp, StringComparison.InvariantCultureIgnoreCase) == 0);
                        if (provider == null) throw new CasHttpException(400, $"\"{flow.idp}\" was not a supported authentication provider.");

                        // defer to the provider
                        await provider.Token(context);

                    }
                    catch (Exception e)
                    {
                        await e.Apply(context);
                    }
                }).RequireCors("cas-server");

                // the extract service can use Javascript to get URL filters and pass them to token
                endpoints.MapGet("/cas/extract", async context =>
                {
                    try
                    {
                        await context.Response.WriteAsync(@"
                            <html>
                                <head>
                                    <script>
                                        document.addEventListener('DOMContentLoaded', function () {
                                            const hash = window.location.hash.substr(1);
                                            for (let opt of hash.split('&')) {
                                                const pair = opt.split('=', 2);
                                                const element = document.getElementById(pair[0]);
                                                if (element) element.value = pair[1];
                                            }
                                            document.auth.submit();
                                        });
                                    </script>
                                </head>
                                <body style='display: none;'>
                                    <form name='auth' method='post' action='/cas/token'>
                                        <input type='text' id='state' name='state' value='' />
                                        <input type='text' id='id_token' name='id_token' value='' />
                                    </form>
                                </body>
                            </html>
                        ");
                    }
                    catch (Exception e)
                    {
                        await e.Apply(context);
                    }
                }).RequireCors("cas-server");

                // define the endpoint for services authenticating with a certificate or secret
                endpoints.MapPost("/cas/service", async context =>
                {
                    try
                    {

                        // hand off to the IDP
                        string idp = context.Request.Query["idp"];
                        if (string.IsNullOrEmpty(idp)) idp = "azure";
                        var providers = context.RequestServices.GetServices<ICasIdp>();
                        var provider = providers.FirstOrDefault(i => string.Compare(i.Id, idp, StringComparison.InvariantCultureIgnoreCase) == 0);
                        if (provider == null) throw new CasHttpException(400, $"\"{idp}\" was not a supported authentication provider.");
                        await provider.Service(context);

                    }
                    catch (Exception e)
                    {
                        await e.Apply(context);
                    }
                }).RequireCors("cas-server");

                // define the endpoint for reissuing tokens
                endpoints.MapPost("/cas/reissue", async context =>
                {
                    try
                    {

                        // TODO: test reissue

                        // get all needed variables
                        var tokenIssuer = context.RequestServices.GetService<CasTokenIssuer>();
                        string token = context.Request.Form["token"];

                        // ensure a token was passed
                        if (string.IsNullOrEmpty(token)) throw new CasHttpException(400, "token was not provided for renewal");

                        // ensure it is eligible for reissue
                        var jwt = await tokenIssuer.IsTokenExpiredButEligibleForRenewal(token);

                        // hand off to the IDP
                        var idp = jwt.Payload.Claims.FirstOrDefault(c => c.Type == "idp");
                        var pid = (idp.Value == null) ? "azure" : idp.Value;
                        var providers = context.RequestServices.GetServices<ICasIdp>();
                        var provider = providers.FirstOrDefault(i => string.Compare(i.Id, pid, StringComparison.InvariantCultureIgnoreCase) == 0);
                        if (provider == null) throw new CasHttpException(400, $"\"{idp}\" was not a supported authentication provider.");
                        var reissued = await provider.Reissue(token);
                        await context.Response.WriteAsync(reissued);

                    }
                    catch (Exception e)
                    {
                        await e.Apply(context);
                    }
                }).RequireCors("cas-server");

                // define the wellknownconfig endpoint
                endpoints.MapGet("/cas/.well-known/openid-configuration", context =>
                {
                    try
                    {

                        // compute the payload
                        // REF: https://ldapwiki.com/wiki/Openid-configuration 
                        // REF: https://developer.byu.edu/docs/consume-api/use-api/implement-openid-connect/openid-connect-discovery
                        var payload = new WellKnownConfigPayload()
                        {
                            issuer = CasEnv.Issuer,
                            jwks_uri = CasEnv.PublicKeysUrl
                        };

                        // return the json
                        string json = JsonConvert.SerializeObject(payload);
                        context.Response.Headers.Add("Content-Type", "application/json; charset=utf-8");
                        return context.Response.WriteAsync(json);

                    }
                    catch (CasHttpException e)
                    {
                        return e.Apply(context);
                    }
                    catch (Exception e)
                    {
                        return e.Apply(context);
                    }
                }).RequireCors("cas-server");

                // define the keys endpoint
                endpoints.MapGet("/cas/keys", async context =>
                {
                    try
                    {

                        // get all needed variables
                        var tokenIssuer = context.RequestServices.GetService<CasTokenIssuer>();

                        // compute the payload
                        var payload = new KeysPayload();
                        var certificates = await tokenIssuer.GetValidationCertificates();
                        foreach (var certificate in certificates)
                        {
                            var key = new Key(certificate);
                            payload.keys.Add(key);
                        }

                        // return the json
                        string json = JsonConvert.SerializeObject(payload);
                        context.Response.Headers.Add("Content-Type", "application/json; charset=utf-8");
                        await context.Response.WriteAsync(json);

                    }
                    catch (Exception e)
                    {
                        await e.Apply(context);
                    }
                }).RequireCors("cas-server");

                // define the verify endpoint which determines if an authentication request is valid
                //  note: this can be used for gateways like APIM to validate the request
                endpoints.MapPost("/cas/verify", async context =>
                {
                    try
                    {

                        // get all needed variables
                        var tokenIssuer = context.RequestServices.GetService<CasTokenIssuer>();

                        // find the tokens in the headers
                        string sessionToken = context.Request.Headers["X-SESSION-TOKEN"];
                        if (string.IsNullOrEmpty(sessionToken)) throw new CasHttpException(400, "X-SESSION-TOKEN header not found");
                        string xsrfToken = context.Request.Headers["X-XSRF-TOKEN"];
                        if (string.IsNullOrEmpty(xsrfToken)) throw new CasHttpException(400, "X-XSRF-TOKEN header not found");

                        // validate the session_token
                        var validatedSessionToken = await tokenIssuer.ValidateToken(sessionToken);
                        var xsrfclaim = validatedSessionToken.Payload.Claims.FirstOrDefault(c => c.Type == "xsrf");
                        if (xsrfclaim == null) throw new CasHttpException(400, "xsrf claim not found in X-SESSION-TOKEN");

                        // validate the xsrf_token (if it is signed)
                        string code = xsrfToken;
                        if (xsrfToken.Length > 32)
                        {
                            var validatedXsrfToken = await tokenIssuer.ValidateToken(xsrfToken);
                            var codeclaim = validatedXsrfToken.Payload.Claims.FirstOrDefault(c => c.Type == "code");
                            if (codeclaim == null) throw new CasHttpException(400, "code claim not found in X-XSRF-TOKEN");
                            code = codeclaim.Value;
                        }

                        // if the code matches, return OK
                        if (xsrfclaim.Value != code) throw new CasHttpException(403, "xsrf claim does not match code claim");
                        await context.Response.CompleteAsync();

                    }
                    catch (Exception e)
                    {
                        await e.Apply(context);
                    }
                }).RequireCors("cas-server");

                // define the type endpoint which shows the selection of authchooser
                endpoints.MapGet("/cas/type", context =>
                {
                    try
                    {
                        switch (CasAuthChooser.AuthType())
                        {
                            case "app":
                                return context.Response.WriteAsync("Application Identity / Service Principal");
                            default:
                                return context.Response.WriteAsync("Managed Identity / az CLI");
                        }
                    }
                    catch (Exception e)
                    {
                        return e.Apply(context);
                    }
                }).RequireCors("cas-server");

                // define the check-requirements endpoint which ensures that all accounts have appropriate access
                endpoints.MapGet("/cas/check-requirements", async context =>
                {
                    try
                    {

                        // get references
                        var logger = context.RequestServices.GetService<ILogger<CasServerAuthMiddleware>>();
                        var httpClientFactory = context.RequestServices.GetService<IHttpClientFactory>();
                        var httpClient = httpClientFactory.CreateClient("cas");
                        var config = context.RequestServices.GetService<ICasConfig>();

                        // validate graph access
                        logger.LogInformation("/cas/check-requirements: checking graph access...");
                        var accessToken = await CasAuthChooser.GetAccessToken("https://graph.microsoft.com", "AUTH_TYPE_GRAPH", config);
                        using (var request = new HttpRequestMessage()
                        {
                            RequestUri = new Uri("https://graph.microsoft.com/beta/users?$top=1"),
                            Method = HttpMethod.Get
                        })
                        {
                            request.Headers.Add("Authorization", $"Bearer {accessToken}");
                            using (var response = await httpClient.SendAsync(request))
                            {
                                if (!response.IsSuccessStatusCode)
                                {
                                    var raw = await response.Content.ReadAsStringAsync();
                                    throw new Exception($"/cas/check-requirements: HTTP {(int)response.StatusCode} - {raw}");
                                }
                            }
                        };
                        logger.LogInformation("/cas/check-requirements: graph access worked as expected.");
                        await context.Response.CompleteAsync();

                    }
                    catch (Exception e)
                    {
                        await e.Apply(context);
                    }
                }).RequireCors("cas-server");

                // define the clear-server-cache endpoint
                endpoints.MapPost("/cas/clear-server-cache", async context =>
                {
                    try
                    {

                        // ensure the user is authorized
                        var config = context.RequestServices.GetService<ICasConfig>();
                        var tokenIssuer = context.RequestServices.GetService<CasTokenIssuer>();
                        var commandPassword = await config.GetString("COMMAND_PASSWORD", CasEnv.CommandPassword);
                        string password = context.Request.Form["password"];
                        if (password != commandPassword) throw new CasHttpException(401, "user did not provide the valid command password");

                        // clear the caches
                        var logger = context.RequestServices.GetService<ILogger<CasServerAuthMiddleware>>();
                        tokenIssuer.ClearSigningKey();
                        logger.LogDebug("The signing key cache was cleared.");
                        tokenIssuer.ClearValidationCertificates();
                        logger.LogDebug("The validation certificate cache was cleared.");

                        // respond with success
                        await context.Response.CompleteAsync();

                    }
                    catch (Exception e)
                    {
                        await e.Apply(context);
                    }
                }).RequireCors("cas-server");

            });
            return builder;

        }





    }

}