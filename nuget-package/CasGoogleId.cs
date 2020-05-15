using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Newtonsoft.Json;

namespace CasAuth
{

    public class CasGoogleId : CasIdp
    {

        public CasGoogleId(
            ILogger<CasGoogleId> logger,
            ICasConfig config,
            CasTokenIssuer tokenIssuer,
            ICasClaimsBuilder claimsBuilder = null,
            ICasAuthCodeReceiver authCodeReceiver = null
        ) : base(logger, config, tokenIssuer, claimsBuilder, authCodeReceiver)
        {
            this.ConfigManager = new ConfigurationManager<OpenIdConnectConfiguration>("https://accounts.google.com/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
        }

        private ConfigurationManager<OpenIdConnectConfiguration> ConfigManager { get; }

        public override string Id { get => "Google"; }

        public override async Task Authorize(HttpContext context)
        {

            // get the necessary variables
            string authority = "https://accounts.google.com";
            string clientId = WebUtility.UrlEncode(CasEnv.GoogleClientId);
            string redirect = WebUtility.UrlEncode(
                // NOTE: google sends the values on a filter, so we need to extract via javascript
                CasEnv.RedirectUri(context.Request).Replace("/cas/token", "/cas/extract")
            );
            string domainHint = WebUtility.UrlEncode(CasEnv.GoogleDomainHint);

            // get the scope
            var basicScope = "openid profile email";
            var scope = await AppendScope(basicScope, "google.com");

            // define the response type
            string responseType = (scope == basicScope)
                ? WebUtility.UrlEncode("id_token")
                : WebUtility.UrlEncode("id_token code");

            // NOTE: I have not tested authcode flow with google yet
            if (scope != basicScope) throw new System.NotSupportedException();

            // write flow cookie
            var flow = WriteFlowCookie(context);

            // redirect to url
            scope = WebUtility.UrlEncode(scope);
            string url = $"{authority}/o/oauth2/v2/auth?response_type={responseType}&client_id={clientId}&redirect_uri={redirect}&scope={scope}&state={flow.state}&nonce={flow.nonce}";
            if (!string.IsNullOrEmpty(domainHint)) url += $"&hd={domainHint}";
            context.Response.Redirect(url);
            await context.Response.CompleteAsync();

        }

        private class Tokens
        {
            public string access_token { get; set; }
            public string refresh_token { get; set; }
        }

        private async Task<JwtSecurityToken> VerifyTokenFromGoogle(string token, string audience = null, string nonce = null)
        {

            // get configuration info from OpenID Connect endpoint
            //  note: this is cached for 1 hour by default
            OpenIdConnectConfiguration config = await ConfigManager.GetConfigurationAsync();

            // determine the possible appropriate issuers
            var issuers = new List<string>() { "https://accounts.google.com", "accounts.google.com" };

            // validate
            var validatedJwt = ValidateTokenFromIdp(token, issuers, audience, nonce, config.SigningKeys);

            return validatedJwt;
        }

        /*
        private async Task<Tokens> GetAccessTokenFromAuthCode(HttpClient httpClient, HttpContext context, ICasConfig config, string code, string scope)
        {

            // get the client secret
            var secret = await config.GetString("CLIENT_SECRET", CasEnv.AzureClientSecret);

            // get the response
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"{CasEnv.AzureAuthority}/oauth2/v2.0/token"),
                Method = HttpMethod.Post
            })
            {
                using (request.Content = new FormUrlEncodedContent(new[] {
                    new KeyValuePair<string, string>("client_id", CasEnv.AzureClientId),
                    new KeyValuePair<string, string>("client_secret", secret),
                    new KeyValuePair<string, string>("scope", scope),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", CasEnv.RedirectUri(context.Request)),
                    new KeyValuePair<string, string>("grant_type", "authorization_code")
                }))
                {
                    using (var response = await httpClient.SendAsync(request))
                    {
                        var raw = await response.Content.ReadAsStringAsync();
                        if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"GetAccessTokenFromAuthCode: HTTP {(int)response.StatusCode} - {raw}");
                        }
                        var tokens = JsonConvert.DeserializeObject<Tokens>(raw);
                        return tokens;
                    }
                }
            };

        }

        private async Task<Tokens> GetAccessTokenFromRefreshToken(HttpClient httpClient, ICasConfig config, string refreshToken, string scope)
        {

            // get the client secret
            var secret = await config.GetString("CLIENT_SECRET", CasEnv.AzureClientSecret);

            // get the response
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"{CasEnv.AzureAuthority}/oauth2/v2.0/token"),
                Method = HttpMethod.Post
            })
            {
                using (request.Content = new FormUrlEncodedContent(new[] {
                    new KeyValuePair<string, string>("client_id", CasEnv.AzureClientId),
                    new KeyValuePair<string, string>("client_secret", secret),
                    new KeyValuePair<string, string>("scope", scope),
                    new KeyValuePair<string, string>("refresh_token", refreshToken),
                    new KeyValuePair<string, string>("grant_type", "refresh_token")
                }))
                {
                    using (var response = await httpClient.SendAsync(request))
                    {
                        var raw = await response.Content.ReadAsStringAsync();
                        if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"GetAccessTokenFromRefreshToken: HTTP {(int)response.StatusCode} - {raw}");
                        }
                        var tokens = JsonConvert.DeserializeObject<Tokens>(raw);
                        return tokens;
                    }
                }
            };

        }

        private async Task<Tokens> GetAccessTokenFromClientSecret(HttpClient httpClient, string clientId, string clientSecret, string scope)
        {

            // get the response
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"{CasEnv.AzureAuthority}/oauth2/v2.0/token"),
                Method = HttpMethod.Post
            })
            {
                using (request.Content = new FormUrlEncodedContent(new[] {
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("client_secret", clientSecret),
                    new KeyValuePair<string, string>("scope", scope),
                    new KeyValuePair<string, string>("grant_type", "client_credentials")
                }))
                {
                    using (var response = await httpClient.SendAsync(request))
                    {
                        var raw = await response.Content.ReadAsStringAsync();
                        if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"GetAccessTokenFromClientSecret: HTTP {(int)response.StatusCode} - {raw}");
                        }
                        var tokens = JsonConvert.DeserializeObject<Tokens>(raw);
                        return tokens;
                    }
                }
            };

        }

        private async Task<Tokens> GetAccessTokenFromClientCertificate(HttpClient httpClient, string clientId, string token, string scope)
        {

            // get the response
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"{CasEnv.AzureAuthority}/oauth2/v2.0/token"),
                Method = HttpMethod.Post
            })
            {
                using (request.Content = new FormUrlEncodedContent(new[] {
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    new KeyValuePair<string, string>("client_assertion", token),
                    new KeyValuePair<string, string>("scope", scope),
                    new KeyValuePair<string, string>("grant_type", "client_credentials")
                }))
                {
                    using (var response = await httpClient.SendAsync(request))
                    {
                        var raw = await response.Content.ReadAsStringAsync();
                        if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"GetAccessTokenFromClientSecret: HTTP {(int)response.StatusCode} - {raw}");
                        }
                        var tokens = JsonConvert.DeserializeObject<Tokens>(raw);
                        return tokens;
                    }
                }
            };

        }
        */

        public override async Task Token(HttpContext context)
        {

            // get the authflow
            if (!context.Request.Cookies.ContainsKey("authflow")) throw new CasHttpException(400, "authflow not provided");
            var flow = JsonConvert.DeserializeObject<CasAuthFlow>(context.Request.Cookies["authflow"]);
            if (context.Request.Form["state"] != flow.state) throw new CasHttpException(400, "state does not match");

            // NOTE: google seems to throw errors on their own domain, they don't return them

            // verify the id_token
            string idRaw = context.Request.Form["id_token"];
            var idToken = await VerifyTokenFromGoogle(idRaw, CasEnv.GoogleClientId, flow.nonce);

            // ensure the email is verified
            if (CasEnv.GoogleEmailMustBeVerified)
            {
                var verified = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "email_verified");
                if (verified.Value != "true") throw new CasHttpException(403, "email was not verified");
            }

            // ICasAuthCodeReceiver: use the code to get an access token
            /* NOTE: I have not tested authcode with google yet
            var authCodeReceiver = context.RequestServices.GetService<ICasAuthCodeReceiver>();
            if (authCodeReceiver != null)
            {
                string code = context.Request.Query["code"];
                Tokens last = null;
                var scopes = await authCodeReceiver.GetAllScopes();
                foreach (var scope in scopes)
                {
                    if (last == null)
                    {
                        last = await GetAccessTokenFromAuthCode(httpClient, context, config, code, "offline_access " + scope);
                    }
                    else
                    {
                        last = await GetAccessTokenFromRefreshToken(httpClient, config, last.refresh_token, "offline_access " + scope);
                    }
                    await authCodeReceiver.ReceiveAll(scope, last.access_token, last.refresh_token);
                    break;
                }
            }
            */

            // build the claims
            var claims = BuildClaims(idToken);
            if (ClaimsBuilder != null)
            {
                await ClaimsBuilder.AddAllClaims(idToken.Payload.Claims, claims);
            }

            // NOTE: google does not have an oid equivalent
            // NOTE: google does not support role claims

            // write the token cookies
            await WriteTokenCookies(context, claims);

            // redirect
            await Redirect(context, flow);

        }

        public override Task Service(HttpContext context)
        {
            throw new System.NotImplementedException();
        }

        public override Task<string> Reissue(string token)
        {
            throw new System.NotImplementedException();
        }

    }

}