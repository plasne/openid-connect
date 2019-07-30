
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
using dotenv.net;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using System.Security.Cryptography;

namespace authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        public AuthController()
        {
            DotEnv.Config(false);
            ConfigManager = new ConfigurationManager<OpenIdConnectConfiguration>($"{TokenIssuer.Authority}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
        }

        private ConfigurationManager<OpenIdConnectConfiguration> ConfigManager { get; }

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
            public string state { get; set; }
            public string nonce { get; set; }
        }

        [AllowAnonymous]
        [HttpGet, Route("authorize")]
        public ActionResult Authorize(string redirecturi)
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
                redirecturi = (string.IsNullOrEmpty(redirecturi)) ? TokenIssuer.AppHome : redirecturi,
                state = this.GenerateSafeRandomString(16),
                nonce = this.GenerateSafeRandomString(16)
            };

            // store the authflow for validating state and nonce later
            //  note: this has to be SameSite=none because it is being POSTed from login.microsoftonline.com
            Response.Cookies.Append("authflow", JsonConvert.SerializeObject(flow), new CookieOptions()
            {
                Expires = DateTimeOffset.Now.AddMinutes(10),
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None
            });

            // build the URL
            string url = $"{authority}/oauth2/v2.0/authorize?response_type={response_type}&client_id={clientId}&redirect_uri={redirectUri}&scope={scope}&response_mode=form_post&state={flow.state}&nonce={flow.nonce}";
            if (!string.IsNullOrEmpty(domainHint)) url += "&domain_hint ={ domainHint}";

            return Redirect(url);
        }

        private async Task<JwtSecurityToken> VerifyIdToken(string token, string nonce)
        {

            // get configuration info from OpenID Connect endpoint
            //  note: this is cached for 1 hour by default
            OpenIdConnectConfiguration config = await this.ConfigManager.GetConfigurationAsync().ConfigureAwait(false);

            // define the validation parameters
            var validationParameters = new TokenValidationParameters
            {
                RequireAudience = true,
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

        private string GetAccessToken(string code, string scope)
        {

            // build the URL
            string url = $"{TokenIssuer.Authority}/oauth2/v2.0/token";

            // get the response
            using (WebClient client = new WebClient())
            {
                NameValueCollection data = new NameValueCollection();
                data.Add("client_id", TokenIssuer.ClientId);
                data.Add("client_secret", TokenIssuer.ClientSecret);
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

        [AllowAnonymous]
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
                    Secure = true,
                    Domain = TokenIssuer.BaseDomain,
                    Path = "/"
                });

                // populate the claims
                List<Claim> claims = new List<Claim>();
                var email = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "email");
                if (email != null) claims.Add(new Claim("email", email.Value));
                var displayName = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "displayName");
                if (displayName != null) claims.Add(new Claim("displayName", displayName.Value));
                var oid = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "oid");
                if (oid != null) claims.Add(new Claim("oid", oid.Value));

                // add the XSRF (cross-site request forgery) claim
                claims.Add(new Claim("xsrf", xsrf));

                // issue the token
                string jwt = await tokenIssuer.IssueToken(claims);
                Response.Cookies.Append("user", jwt, new CookieOptions()
                {
                    HttpOnly = true,
                    Secure = true,
                    Domain = TokenIssuer.BaseDomain,
                    Path = "/"
                });

                return Redirect(flow.redirecturi);
            }
            catch (Exception e)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, e.Message);
            }
        }

        [Authorize]
        [HttpGet, Route("hello")]
        public ActionResult<IEnumerable<string>> Hello()
        {
            List<string> list = new List<string>();
            var identity = User.Identity as ClaimsIdentity;
            foreach (var claim in identity.Claims)
            {
                list.Add($"{claim.Type}: {claim.Value}");
            }
            return Ok(list);
        }

        [AllowAnonymous]
        [HttpGet, Route("version")]
        public ActionResult<string> Version()
        {
            return "v1.3.0";
        }

    }

}
