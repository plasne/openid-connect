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
using System.Security.Cryptography.X509Certificates;

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
            public string state { get; set; }
            public string nonce { get; set; }
        }

        [HttpGet, Route("authorize")]
        public ActionResult Authorize(string redirecturi)
        {
            try
            {

                // get the necessary variables
                string authority = TokenIssuer.Authority;
                string clientId = WebUtility.UrlEncode(TokenIssuer.ClientId);
                string redirectUri = WebUtility.UrlEncode(TokenIssuer.RedirectUri);
                // REF: https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
                string scope = WebUtility.UrlEncode("openid profile email"); // space sep (ex. https://graph.microsoft.com/user.read)
                string response_type = WebUtility.UrlEncode("id_token"); // space sep, could include "code"
                string domainHint = WebUtility.UrlEncode(TokenIssuer.DomainHint);

                // generate state and nonce
                AuthFlow flow = new AuthFlow()
                {
                    redirecturi = (string.IsNullOrEmpty(redirecturi)) ? TokenIssuer.DefaultRedirectUrl : redirecturi,
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
            Logger.LogDebug($"id_token: {token}");

            // get configuration info from OpenID Connect endpoint
            //  note: this is cached for 1 hour by default
            OpenIdConnectConfiguration config = await this.ConfigManager.GetConfigurationAsync();

            // determine the appropriate issuer
            string issuer = $"{TokenIssuer.Authority}/v2.0";
            var handler = new JwtSecurityTokenHandler();
            if (TokenIssuer.Authority.EndsWith("/common"))
            {
                var unvalidatedJwt = handler.ReadJwtToken(token);
                var tid = unvalidatedJwt.Payload.Claims.FirstOrDefault(c => c.Type == "tid");
                if (tid != null) issuer = $"https://login.microsoftonline.com/{tid.Value}/v2.0";
            }

            // define the validation parameters
            var validationParameters = new TokenValidationParameters
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = true,
                ValidAudience = TokenIssuer.ClientId,
                ValidateLifetime = true,
                IssuerSigningKeys = config.SigningKeys
            };

            // validate all previously defined parameters
            SecurityToken validatedSecurityToken = null;
            handler.ValidateToken(token, validationParameters, out validatedSecurityToken);
            JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;

            // validate alg and nonce
            if (validatedJwt.Header.Alg != SecurityAlgorithms.RsaSha256) throw new SecurityTokenValidationException("The alg must be RS256.");
            if (validatedJwt.Payload.Nonce != nonce) throw new SecurityTokenValidationException("The nonce was invalid.");

            return validatedJwt;
        }

        private class Tokens
        {
            public string accessToken { get; set; }
            public string refreshToken { get; set; }
        }

        private Tokens GetAccessTokenFromAuthCode(string code, string scope, TokenIssuer tokenIssuer)
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
                return new Tokens()
                {
                    accessToken = json.access_token,
                    refreshToken = json.refresh_token
                };
            }

        }

        private Tokens GetAccessTokenFromRefreshToken(string refreshToken, string scope, TokenIssuer tokenIssuer)
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
                data.Add("refresh_token", refreshToken);
                data.Add("grant_type", "refresh_token");
                byte[] response = client.UploadValues(url, data);
                string result = System.Text.Encoding.UTF8.GetString(response);
                dynamic json = JObject.Parse(result);
                return new Tokens()
                {
                    accessToken = json.access_token,
                    refreshToken = json.refresh_token
                };
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

                // AuthCode: use the code to get an access token
                /*
                string code = Request.Form["code"];
                var tokens1 = GetAccessTokenFromAuthCode(code, "offline_access https://graph.microsoft.com/user.read", tokenIssuer);
                Console.WriteLine("access_token[0]: " + tokens1.accessToken);
                var tokens2 = GetAccessTokenFromRefreshToken(tokens1.refreshToken, "offline_access https://analysis.windows.net/powerbi/api/dataset.read", tokenIssuer);
                Console.WriteLine("access_token[1]: " + tokens2.accessToken);
                */

                // populate the claims from the id_token
                List<Claim> claims = new List<Claim>();
                var email = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "email");
                if (email != null) claims.Add(new Claim("email", email.Value));
                var displayName = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "name");
                if (displayName != null) claims.Add(new Claim("displayName", displayName.Value));

                // get the oid
                if (TokenIssuer.Authority.EndsWith("/common"))
                {

                    // add the tenant claim
                    var tid = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "tid");
                    if (tid != null) claims.Add(new Claim("tenant", tid.Value));

                    // oids for external users are wrong, we need to query for them
                    var oid = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "oid");
                    if (oid != null)
                    {
                        if (await tokenIssuer.GetUserById(oid.Value) == null)
                        {
                            // query by userPrincipalName
                            var username = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "preferred_username");
                            if (username != null)
                            {
                                string userId = username.Value.Replace("@", "_");
                                var users = await tokenIssuer.GetUserById($"/?$filter=startsWith(userPrincipalName, '{userId}%23EXT%23')");
                                if (users != null && users.value.Count > 0)
                                {
                                    claims.Add(new Claim("oid", (string)users.value[0].id));
                                }
                            }
                        }
                        else
                        {
                            // the oid was valid; the user is local
                            claims.Add(new Claim("oid", oid.Value));
                        }
                    }

                }
                else
                {
                    // oids for 1st party users are fine
                    var oid = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "oid");
                    if (oid != null) claims.Add(new Claim("oid", oid.Value));

                }

                // attempt to propogate roles
                var roles = idToken.Payload.Claims.Where(c => c.Type == "roles");
                foreach (var role in roles)
                {
                    claims.Add(new Claim("roles", role.Value));
                }

                // Service-to-Service: get other claims from the graph (req. Directory.Read.All)
                //    or from a database
                /*
                dynamic user = await tokenIssuer.GetUserById(oid.Value);
                claims.Add(new Claim("displayName2", (string)user.displayName));
                */

                // write the XSRF-TOKEN cookie (if it will be verified)
                if (TokenIssuer.VerifyXsrfInHeader || TokenIssuer.VerifyXsrfInCookie)
                {
                    string xsrf = this.GenerateSafeRandomString(16);
                    string signed = xsrf;
                    if (!TokenIssuer.RequireHttpOnlyOnUserCookie)
                    {
                        // if the source claim is going to be in a cookie that is readable by JavaScript the XSRF must be signed
                        signed = tokenIssuer.IssueXsrfToken(xsrf);
                    }
                    Response.Cookies.Append("XSRF-TOKEN", signed, new CookieOptions()
                    {
                        HttpOnly = TokenIssuer.RequireHttpOnlyOnXsrfCookie,
                        Secure = TokenIssuer.RequireSecureForCookies,
                        Domain = TokenIssuer.BaseDomain,
                        Path = "/"
                    });
                    claims.Add(new Claim("xsrf", xsrf));
                }

                // write the user cookie
                string jwt = await tokenIssuer.IssueToken(claims);
                Response.Cookies.Append("user", jwt, new CookieOptions()
                {
                    HttpOnly = TokenIssuer.RequireHttpOnlyOnUserCookie,
                    Secure = TokenIssuer.RequireSecureForCookies,
                    Domain = TokenIssuer.BaseDomain,
                    Path = "/"
                });

                // revoke the authflow cookie
                Response.Cookies.Delete("authflow");

                return Redirect(flow.redirecturi);
            }
            catch (Exception e)
            {
                Logger.LogError(e, "exception on api/auth/token");
                return StatusCode(StatusCodes.Status500InternalServerError, e.Message);
            }
        }

        [HttpPost, Route("reissue")]
        public async Task<ActionResult> Reissue([FromForm] string token, [FromServices] TokenIssuer tokenIssuer)
        {
            try
            {

                // ensure a token was passed
                if (string.IsNullOrEmpty(token)) throw new Exception("token was not provided for renewal");

                // see if it is eligible for reissue (an exception will be thrown if not)
                var reissued = await tokenIssuer.ReissueToken(token);

                return Ok(reissued);
            }
            catch (Exception e)
            {
                Logger.LogError(e, "exception on api/auth/reissue");
                return BadRequest(e.Message);
            }
        }

        public class WellKnownConfigPayload
        {
            public string issuer { get; set; }
            public string jwks_uri { get; set; }
        }

        [HttpGet, Route(".well-known/openid-configuration")]
        public ActionResult<dynamic> WellKnownConfig()
        {
            // REF: https://ldapwiki.com/wiki/Openid-configuration 
            // REF: https://developer.byu.edu/docs/consume-api/use-api/implement-openid-connect/openid-connect-discovery
            return new WellKnownConfigPayload()
            {
                issuer = TokenIssuer.Issuer,
                jwks_uri = TokenIssuer.PublicKeysUrl
            };
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

        [HttpGet, Route("keys")]
        public ActionResult<KeysPayload> Keys([FromServices] TokenIssuer tokenIssuer)
        {
            var payload = new KeysPayload();
            foreach (var certificate in tokenIssuer.ValidationCertificates)
            {
                var key = new Key(certificate);
                payload.keys.Add(key);
            }
            return payload;
        }

        [HttpPost, Route("verify")]
        public ActionResult Verify([FromServices] TokenIssuer tokenIssuer)
        {
            try
            {

                // find the tokens in the headers
                string sessionToken = Request.Headers["X-SESSION-TOKEN"];
                if (string.IsNullOrEmpty(sessionToken)) throw new Exception("X-SESSION-TOKEN header not found");
                string xsrfToken = Request.Headers["X-XSRF-TOKEN"];
                if (string.IsNullOrEmpty(xsrfToken)) throw new Exception("X-XSRF-TOKEN header not found");

                // validate the session_token
                var validatedSessionToken = tokenIssuer.ValidateToken(sessionToken);
                var xsrfclaim = validatedSessionToken.Payload.Claims.FirstOrDefault(c => c.Type == "xsrf");
                if (xsrfclaim == null) throw new Exception("xsrf claim not found in X-SESSION-TOKEN");

                // validate the xsrf_token (if it is signed)
                string code = xsrfToken;
                if (xsrfToken.Length > 32)
                {
                    var validatedXsrfToken = tokenIssuer.ValidateToken(xsrfToken);
                    var codeclaim = validatedXsrfToken.Payload.Claims.FirstOrDefault(c => c.Type == "code");
                    if (codeclaim == null) throw new Exception("code claim not found in X-XSRF-TOKEN");
                    code = codeclaim.Value;
                }

                if (xsrfclaim.Value != code) throw new Exception("xsrf claim does not match code claim");
                return Ok();
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }
        }

        [HttpPost, Route("clear-cache")]
        public ActionResult ClearCache([FromForm] string password, [FromForm] string scope, [FromServices] TokenIssuer tokenIssuer)
        {
            if (string.IsNullOrEmpty(tokenIssuer.CommandPassword) || tokenIssuer.CommandPassword == password)
            {
                if (!string.IsNullOrEmpty(scope))
                {
                    var scopes = scope.Split(',').Select(id => id.Trim());

                    // clear signing-key
                    if (scopes.Contains("signing-key"))
                    {
                        tokenIssuer.ClearSigningKey();
                        Logger.LogDebug("The signing key cache was cleared.");
                    }

                    // clear validation-certificates
                    if (scopes.Contains("validation-certificates"))
                    {

                        tokenIssuer.ClearValidationCertificates();
                        Logger.LogDebug("The validation certificate cache was cleared.");
                    }

                }
                return Ok();
            }
            else
            {
                return Unauthorized("password did not match COMMAND_PASSWORD");
            }
        }

        [HttpGet, Route("version")]
        public ActionResult<string> Version()
        {
            Logger.LogDebug("/api/token/version service ping");
            return "v3.0.0";
        }

        [HttpGet, Route("type")]
        public ActionResult<string> Type()
        {
            switch (AuthChooser.AuthType())
            {
                case "app":
                    return "Application Identity / Service Principal";
                default:
                    return "Managed Identity / az CLI";
            }
        }

        [HttpGet, Route("check-requirements")]
        public async Task<ActionResult> CheckRequirements(string scope)
        {
            List<string> errors = new List<string>();
            var tokenProvider = new AzureServiceTokenProvider();
            scope = scope.ToLower();
            if (string.IsNullOrEmpty(scope)) scope = "graph";

            // test graph access
            if (scope.Contains("graph"))
            {
                try
                {
                    var graphToken = await tokenProvider.GetAccessTokenAsync("https://graph.microsoft.com");
                    using (var client = new WebClient())
                    {
                        if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
                        client.Headers.Add("Authorization", $"Bearer {graphToken}");
                        string query = "https://graph.microsoft.com/beta/users?$top=1";
                        client.DownloadString(new Uri(query));
                    }
                }
                catch (Exception e)
                {
                    Logger.LogError(e, "verify Graph failed");
                    errors.Add($"graph - {e.Message}");
                }
            }

            // report on the verification
            if (errors.Count < 1)
            {
                return Ok("all tests passed");
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, string.Join("; ", errors));
            }

        }

    }

}
