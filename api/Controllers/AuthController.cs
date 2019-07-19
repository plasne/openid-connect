
using System;
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
using Microsoft.Graph;
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
            ConfigManager = new ConfigurationManager<OpenIdConnectConfiguration>($"{this.Authority}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
        }

        private ConfigurationManager<OpenIdConnectConfiguration> ConfigManager { get; }

        private string Authority
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("AUTHORITY");
            }
        }

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

        private string RedirectUri
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("REDIRECT_URI");
            }
        }

        private string SigningKey
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("SIGNING_KEY");
            }
        }

        private string Issuer
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("ISSUER");
            }
        }

        private string Audience
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("AUDIENCE");
            }
        }

        private string AppHome
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("APP_HOME");
            }
        }

        private bool Secure
        {
            get
            {
                return (String.Compare(System.Environment.GetEnvironmentVariable("SECURE"), "false", true) != 0);
            }
        }

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
            string authority = this.Authority;
            string clientId = WebUtility.UrlEncode(this.ClientId);
            string redirectUri = WebUtility.UrlEncode(this.RedirectUri);
            string scope = WebUtility.UrlEncode("openid https://graph.microsoft.com/user.read"); // space sep
            string response_type = WebUtility.UrlEncode("id_token code");

            // generate state and nonce
            AuthFlow flow = new AuthFlow()
            {
                redirecturi = (string.IsNullOrEmpty(redirecturi)) ? this.AppHome : redirecturi,
                state = this.GenerateSafeRandomString(16),
                nonce = this.GenerateSafeRandomString(16)
            };

            // store the authflow for validating state and nonce later
            //  note: this has to be SameSite=none because it is being POSTed from login.microsoftonline.com
            Response.Cookies.Append("authflow", JsonConvert.SerializeObject(flow), new CookieOptions()
            {
                Expires = DateTimeOffset.Now.AddMinutes(10),
                HttpOnly = true,
                Secure = this.Secure,
                SameSite = SameSiteMode.None
            });

            // build the URL
            string url = $"{authority}/oauth2/v2.0/authorize?response_type={response_type}&client_id={clientId}&redirect_uri={redirectUri}&scope={scope}&response_mode=form_post&state={flow.state}&nonce={flow.nonce}";

            return Redirect(url);
        }

        private async Task VerifyToken(string token, string nonce)
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
                ValidIssuer = $"{this.Authority}/v2.0",
                ValidateAudience = true,
                ValidAudience = this.ClientId,
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

        }

        private async Task<User> GetUser(string token)
        {

            // create graph client
            var graphServiceClient = new GraphServiceClient(new DelegateAuthenticationProvider((requestMessage) =>
            {
                requestMessage
                    .Headers
                    .Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("bearer", token);
                return Task.FromResult(0);
            }));

            // return the user info
            return await graphServiceClient
            .Me
            .Request()
            .Select("displayName, mail")
            .GetAsync();

        }

        private string GetAccessToken(string code, string scope)
        {

            // build the URL
            string url = $"{this.Authority}/oauth2/v2.0/token";

            // get the response
            using (WebClient client = new WebClient())
            {
                NameValueCollection data = new NameValueCollection();
                data.Add("client_id", this.ClientId);
                data.Add("client_secret", this.ClientSecret);
                data.Add("scope", scope);
                data.Add("code", code);
                data.Add("redirect_uri", this.RedirectUri);
                data.Add("grant_type", "authorization_code");
                byte[] response = client.UploadValues(url, data);
                string result = System.Text.Encoding.UTF8.GetString(response);
                dynamic json = JObject.Parse(result);
                // json.refresh_token is also available
                return json.access_token;
            }

        }

        private static string GetBaseDomain(Uri uri)
        {
            var host = uri.Host;
            var parts = host.Split(".");
            if (parts.Length < 2) return host;
            return $"{parts[parts.Length - 2]}.{parts[parts.Length - 1]}";
        }

        [AllowAnonymous]
        [HttpPost, Route("token")]
        public async Task<ActionResult> Token()
        {
            try
            {

                // read flow, verify state and nonce
                if (!Request.Cookies.ContainsKey("authflow")) throw new UnauthorizedAccessException("authflow not provided");
                AuthFlow flow = JsonConvert.DeserializeObject<AuthFlow>(Request.Cookies["authflow"]);
                if (Request.Form["state"] != flow.state) throw new UnauthorizedAccessException("state does not match");

                // verify the id token
                string id = Request.Form["id_token"];
                await VerifyToken(id, flow.nonce);

                // NOTE: this particular workflow isn't a realistic one (the data being read from the graph is info we already have
                //   in the id_token), but just showcases how to authenticate, collect info about the user from various sources, and
                //   build a JWT to act as session state. A more realistic workflow might be to read specific group membership and
                //   use that to determine roles, to read user info from a database, etc.

                // use the code to get an access token
                string code = Request.Form["code"];
                string token = GetAccessToken(code, "offline_access https://graph.microsoft.com/user.read");

                // use the token to get user info
                User me = await GetUser(token);

                // write the X-XSRF-TOKEN
                string xsrf = this.GenerateSafeRandomString(16);
                Response.Cookies.Append("XSRF-TOKEN", xsrf, new CookieOptions()
                {
                    Expires = DateTimeOffset.Now.AddHours(4),
                    Secure = this.Secure,
                    Domain = GetBaseDomain(new Uri(this.AppHome)),
                    Path = "/"
                });

                // populate the claims
                List<Claim> claims = new List<Claim>();
                if (!string.IsNullOrEmpty(me.DisplayName)) claims.Add(new Claim("displayName", me.DisplayName));
                if (!string.IsNullOrEmpty(me.Mail)) claims.Add(new Claim("email", me.Mail));
                claims.Add(new Claim("xsrf", xsrf));
                claims.Add(new Claim("roles", "user"));

                // sign the token
                var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(this.SigningKey));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                // generate the token
                var jwt = new JwtSecurityToken(
                    issuer: this.Issuer,
                    audience: this.Audience,
                    claims: claims,
                    expires: DateTime.Now.AddHours(4),
                    signingCredentials: creds);

                // write to string
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                string jwt_s = handler.WriteToken(jwt);

                // write the identity to a cookie
                Response.Cookies.Append("user", jwt_s, new CookieOptions()
                {
                    Expires = DateTimeOffset.Now.AddHours(4),
                    HttpOnly = true,
                    Secure = this.Secure,
                    Domain = GetBaseDomain(new Uri(this.AppHome)),
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
