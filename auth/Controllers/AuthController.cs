using System;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.Services.AppAuthentication;

namespace authentication.Controllers
{
    [Route("api/[controller]")]
    [AllowAnonymous]
    [ApiController]
    public class AuthController : ControllerBase
    {

        public AuthController(ILogger<AuthController> logger)
        {
            this.ConfigManager = new ConfigurationManager<OpenIdConnectConfiguration>($"{TokenIssuer.Authority}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
            this.Logger = logger;
        }

        private ConfigurationManager<OpenIdConnectConfiguration> ConfigManager { get; }
        private ILogger Logger { get; }

        private string GenerateSafeRandomString(int length)
        {
            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
            var bytes = new byte[length];
            provider.GetBytes(bytes);
            string s = Convert.ToBase64String(bytes);
            s = s.Split('=')[0];
            s = s.Replace('+', '-');
            s = s.Replace('/', '_');
            return s;
        }

        private class AuthFlow
        {
            public string redirecturi { get; set; }
            public string basedomain { get; set; }
            public string state { get; set; }
            public string nonce { get; set; }
        }

        [HttpGet, Route("authorize")]
        public ActionResult Authorize(string redirecturi, string basedomain)
        {
            try
            {

                // get the necessary variables
                string authority = TokenIssuer.Authority;
                string clientId = WebUtility.UrlEncode(TokenIssuer.ClientId);
                string redirectUri = WebUtility.UrlEncode(TokenIssuer.RedirectUri);
                string scope = WebUtility.UrlEncode("openid"); // space sep (ex. https://graph.microsoft.com/user.read)
                string response_type = WebUtility.UrlEncode("id_token"); // space sep, could include "code"
                string domainHint = WebUtility.UrlEncode(TokenIssuer.DomainHint);

                // generate state and nonce
                AuthFlow flow = new AuthFlow()
                {
                    redirecturi = (string.IsNullOrEmpty(redirecturi)) ? TokenIssuer.DefaultRedirectUrl : redirecturi,
                    basedomain = (string.IsNullOrEmpty(basedomain)) ? TokenIssuer.BaseDomain : basedomain,
                    state = this.GenerateSafeRandomString(16),
                    nonce = this.GenerateSafeRandomString(16)
                };

                // store the authflow for validating state and nonce later
                //  note: this has to be SameSite=none because it is being POSTed from login.microsoftonline.com
                Response.Cookies.Append("authflow", JsonConvert.SerializeObject(flow), new CookieOptions()
                {
                    Expires = DateTimeOffset.Now.AddMinutes(10),
                    HttpOnly = true,
                    Secure = TokenIssuer.RequireSecureForCookies,
                    SameSite = SameSiteMode.None
                });

                // build the URL
                string url = $"{authority}/oauth2/v2.0/authorize?response_type={response_type}&client_id={clientId}&redirect_uri={redirectUri}&scope={scope}&response_mode=form_post&state={flow.state}&nonce={flow.nonce}";
                if (!string.IsNullOrEmpty(domainHint)) url += $"&domain_hint={domainHint}";

                return Redirect(url);
            }
            catch (Exception e)
            {
                Logger.LogError(e, "exception on api/auth/authorize");
                return StatusCode(StatusCodes.Status500InternalServerError, e.Message);
            }
        }

        private async Task<JwtSecurityToken> VerifyIdToken(string token, string nonce)
        {

            // get configuration info from OpenID Connect endpoint
            //  note: this is cached for 1 hour by default
            OpenIdConnectConfiguration config = await this.ConfigManager.GetConfigurationAsync().ConfigureAwait(false);

            // define the validation parameters
            var validationParameters = new TokenValidationParameters
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuer = $"{TokenIssuer.Authority}/v2.0",
                ValidateAudience = true,
                ValidAudience = TokenIssuer.ClientId,
                ValidateLifetime = true,
                IssuerSigningKeys = config.SigningKeys
            };

            // validate all previously defined parameters
            SecurityToken validatedSecurityToken = null;
            var handler = new JwtSecurityTokenHandler();
            handler.ValidateToken(token, validationParameters, out validatedSecurityToken);
            JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;

            // validate alg and nonce
            if (validatedJwt.Header.Alg != SecurityAlgorithms.RsaSha256) throw new SecurityTokenValidationException("The alg must be RS256.");
            if (validatedJwt.Payload.Nonce != nonce) throw new SecurityTokenValidationException("The nonce was invalid.");

            return validatedJwt;
        }

        private string GetAccessToken(string code, string scope, [FromServices] TokenIssuer tokenIssuer)
        {

            // build the URL
            string url = $"{TokenIssuer.Authority}/oauth2/v2.0/token";

            // get the response
            using (WebClient client = new WebClient())
            {
                if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
                NameValueCollection data = new NameValueCollection();
                data.Add("client_id", TokenIssuer.ClientId);
                data.Add("client_secret", tokenIssuer.ClientSecret);
                data.Add("scope", scope);
                data.Add("code", code);
                data.Add("redirect_uri", TokenIssuer.RedirectUri);
                data.Add("grant_type", "authorization_code");
                byte[] response = client.UploadValues(url, data);
                string result = System.Text.Encoding.UTF8.GetString(response);
                dynamic json = JObject.Parse(result);
                // json.refresh_token is also available
                return json.access_token;
            }

        }

        [HttpPost, Route("token")]
        public async Task<ActionResult> Token([FromServices] TokenIssuer tokenIssuer)
        {
            try
            {

                // read flow, verify state and nonce
                if (!Request.Cookies.ContainsKey("authflow")) throw new UnauthorizedAccessException("authflow not provided");
                AuthFlow flow = JsonConvert.DeserializeObject<AuthFlow>(Request.Cookies["authflow"]);
                if (Request.Form["state"] != flow.state) throw new UnauthorizedAccessException("state does not match");

                // verify the id token
                string idRaw = Request.Form["id_token"];
                var idToken = await VerifyIdToken(idRaw, flow.nonce);

                // use the code to get an access token
                /*
                string code = Request.Form["code"];
                string token = GetAccessToken(code, "offline_access https://graph.microsoft.com/user.read");
                */

                // write the XSRF-TOKEN cookie
                string xsrf = this.GenerateSafeRandomString(16);
                Response.Cookies.Append("XSRF-TOKEN", xsrf, new CookieOptions()
                {
                    Secure = TokenIssuer.RequireSecureForCookies,
                    Domain = flow.basedomain,
                    Path = "/"
                });

                // populate the claims from the id_token
                List<Claim> claims = new List<Claim>();
                var email = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "email");
                if (email != null) claims.Add(new Claim("email", email.Value));

                // populate the claims from the user's graph object
                dynamic user = await tokenIssuer.GetUserByEmail(email.Value);
                claims.Add(new Claim("displayName", (string)user.displayName));
                claims.Add(new Claim("oid", (string)user.id));

                // add the XSRF (cross-site request forgery) claim
                claims.Add(new Claim("xsrf", xsrf));

                // issue the token
                string jwt = await tokenIssuer.IssueToken(claims);
                Response.Cookies.Append("user", jwt, new CookieOptions()
                {
                    HttpOnly = true,
                    Secure = TokenIssuer.RequireSecureForCookies,
                    Domain = flow.basedomain,
                    Path = "/"
                });

                return Redirect(flow.redirecturi);
            }
            catch (Exception e)
            {
                Logger.LogError(e, "exception on api/auth/token");
                return StatusCode(StatusCodes.Status500InternalServerError, e.Message);
            }
        }

        [HttpPost, Route("reissue")]
        public async Task<ActionResult> Reissue([FromForm] string token, [FromForm] string basedomain, [FromServices] TokenIssuer tokenIssuer)
        {
            try
            {

                // ensure a token was passed
                if (string.IsNullOrEmpty(token)) throw new Exception("token was not provided for renewal");

                // see if it is eligible for reissue (an exception will be thrown if not)
                var reissued = await tokenIssuer.ReissueToken(token);

                // rewrite the cookie
                Response.Cookies.Append("user", reissued, new CookieOptions()
                {
                    HttpOnly = true,
                    Secure = TokenIssuer.RequireSecureForCookies,
                    Domain = string.IsNullOrEmpty(basedomain) ? TokenIssuer.BaseDomain : basedomain,
                    Path = "/"
                });

                return Ok(reissued);
            }
            catch (Exception e)
            {
                Logger.LogError(e, "exception on api/auth/reissue");
                return BadRequest(e.Message);
            }
        }

        [HttpGet, Route("certificate")]
        public ActionResult<string> PublicValidationCertificate([FromServices] TokenIssuer tokenIssuer)
        {
            return tokenIssuer.ValidationCertificate;
        }

        [HttpGet, Route("issue")]
        public async Task<ActionResult<string>> Issue([FromServices] TokenIssuer tokenIssuer)
        {
            var claims = new List<Claim>();
            claims.Add(new Claim("oid", "d5c1d5d5-fa31-4ec3-9ad3-d520b7772ad7"));
            claims.Add(new Claim("displayName", "Lasne, Peter"));
            claims.Add(new Claim("uniqueName", "pelasne"));
            claims.Add(new Claim("email", "pelasne@microsoft.com"));
            claims.Add(new Claim("xsrf", "secret"));
            return await tokenIssuer.IssueToken(claims);
        }

        [HttpGet, Route("version")]
        public ActionResult<string> Version()
        {
            Logger.LogDebug("/api/token/version service ping");
            return "v3.0.0";
        }

        [HttpGet, Route("verify")]
        public async Task<ActionResult> Verify()
        {
            try
            {

                // this method allows you to test whether the appropriate permissions are assigned
                var tokenProvider = new AzureServiceTokenProvider();

                // test vault access
                var vaultToken = await tokenProvider.GetAccessTokenAsync("https://vault.azure.net");
                using (var client = new WebClient())
                {
                    if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
                    client.Headers.Add("Authorization", $"Bearer {vaultToken}");
                    client.DownloadString(new Uri($"{TokenIssuer.KeyVaultPublicCertUrl}?api-version=7.0"));
                }

                // test graph access
                var graphToken = await tokenProvider.GetAccessTokenAsync("https://graph.microsoft.com");
                using (var client = new WebClient())
                {
                    if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
                    client.Headers.Add("Authorization", $"Bearer {graphToken}");
                    string query = "https://graph.microsoft.com/beta/users?$top=1";
                    client.DownloadString(new Uri(query));
                }

                return Ok("all tests passed");
            }
            catch (Exception e)
            {
                Logger.LogError(e, "verify failed");
                return StatusCode(StatusCodes.Status500InternalServerError, e.Message);
            }
        }

    }

}
