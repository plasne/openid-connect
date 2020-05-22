using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace CasAuth
{

    public abstract class CasIdp : ICasIdp
    {

        public CasIdp(
            ILogger logger,
            CasTokenIssuer tokenIssuer,
            ICasClaimsBuilder claimsBuilder = null,
            ICasAuthCodeReceiver authCodeReceiver = null
        )
        {
            this.Logger = logger;
            this.TokenIssuer = tokenIssuer;
            this.ClaimsBuilder = claimsBuilder;
            this.AuthCodeReceiver = authCodeReceiver;
        }

        protected ILogger Logger { get; }
        protected CasTokenIssuer TokenIssuer { get; }
        protected ICasClaimsBuilder ClaimsBuilder { get; }
        protected ICasAuthCodeReceiver AuthCodeReceiver { get; }

        public abstract string Id { get; }
        public abstract Task Authorize(HttpContext context);
        public abstract Task Service(HttpContext context);
        public abstract Task Token(HttpContext context);
        public abstract Task<string> Reissue(string token);

        protected string GenerateSafeRandomString(int length)
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

        protected async Task<string> AppendScope(string scope, string filterTo)
        {
            // REF: https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
            if (AuthCodeReceiver != null)
            {
                var scopes = await AuthCodeReceiver.GetAllScopes();
                foreach (var s in scopes)
                {
                    if (s.Contains(filterTo)) scope += $" {s}";
                }
            }
            return scope;
        }

        protected CasAuthFlow WriteFlowCookie(HttpContext context)
        {

            // generate state and nonce
            CasAuthFlow flow = new CasAuthFlow()
            {
                idp = this.Id,
                state = this.GenerateSafeRandomString(32),
                nonce = this.GenerateSafeRandomString(32)
            };

            // determine redirect
            string redirect = context.Request.Query["redirecturi"];
            if (!string.IsNullOrEmpty(redirect))
            {
                flow.redirecturi = redirect;
            }
            else if (!string.IsNullOrEmpty(CasConfig.DefaultRedirectUrl))
            {
                flow.redirecturi = CasConfig.DefaultRedirectUrl;
            }

            // store the authflow for validating state and nonce later
            //  NOTE: this has to be SameSite=none because it is being POSTed from an external IDP
            context.Response.Cookies.Append("authflow", JsonConvert.SerializeObject(flow), new CookieOptions()
            {
                Expires = DateTimeOffset.Now.AddMinutes(10),
                HttpOnly = true,
                Secure = CasConfig.RequireSecureForCookies,
                SameSite = SameSiteMode.None
            });

            return flow;
        }

        protected JwtSecurityToken ValidateTokenFromIdp(string token, List<string> issuers, string audience, string nonce, ICollection<SecurityKey> keys)
        {

            // define the validation parameters
            var validationParameters = new TokenValidationParameters
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuers = issuers.ToArray(),
                ValidateAudience = (!string.IsNullOrEmpty(audience)),
                ValidAudience = audience,
                ValidateLifetime = true,
                IssuerSigningKeys = keys
            };

            // validate all previously defined parameters
            var handler = new JwtSecurityTokenHandler();
            SecurityToken validatedSecurityToken = null;
            handler.ValidateToken(token, validationParameters, out validatedSecurityToken);
            JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;

            // validate alg
            if (validatedJwt.Header.Alg != SecurityAlgorithms.RsaSha256) throw new SecurityTokenValidationException("The alg must be RS256.");

            // validate nonce
            if (string.IsNullOrEmpty(nonce))
            {
                // nonce not provided
            }
            else if (validatedJwt.Payload.Nonce != nonce)
            {
                throw new SecurityTokenValidationException("The nonce was invalid.");
            }

            return validatedJwt;
        }

        protected List<Claim> BuildClaims(JwtSecurityToken idToken)
        {
            List<Claim> claims = new List<Claim>();

            // email and name are always the same in OIDC
            var email = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "email");
            if (email != null) claims.AddShort("email", email.Value);
            var name = idToken.Payload.Claims.FirstOrDefault(c => c.Type == "name");
            if (name != null) claims.AddShort("name", name.Value);

            // we need to add a claim for the idp to support reissue
            claims.AddShort("idp", this.Id);

            return claims;
        }

        protected async Task WriteTokenCookies(HttpContext context, List<Claim> claims)
        {
            var domain = CasConfig.BaseDomain(context.Request);

            // write the XSRF-TOKEN cookie (if it will be verified)
            if (CasConfig.VerifyXsrfInHeader || CasConfig.VerifyXsrfInCookie)
            {
                string xsrf = this.GenerateSafeRandomString(16);
                string signed = xsrf;
                if (!CasConfig.RequireHttpOnlyOnUserCookie)
                {
                    // if the source claim is going to be in a cookie that is readable by JavaScript the XSRF must be signed
                    signed = await TokenIssuer.IssueXsrfToken(xsrf);
                }
                context.Response.Cookies.Append("XSRF-TOKEN", signed, new CookieOptions()
                {
                    HttpOnly = CasConfig.RequireHttpOnlyOnXsrfCookie,
                    Secure = CasConfig.RequireSecureForCookies,
                    Domain = domain,
                    SameSite = CasConfig.SameSite,
                    Path = "/"
                });
                Logger.LogInformation($"wrote XSRF-TOKEN cookie on domain \"{domain}\".");
                claims.Add(new Claim("xsrf", xsrf));
            }

            // write the user cookie
            string jwt = await TokenIssuer.IssueToken(claims);
            var userCookie = CasConfig.UserCookieName;
            context.Response.Cookies.Append(userCookie, jwt, new CookieOptions()
            {
                HttpOnly = CasConfig.RequireHttpOnlyOnUserCookie,
                Secure = CasConfig.RequireSecureForCookies,
                Domain = domain,
                SameSite = CasConfig.SameSite,
                Path = "/"
            });
            Logger.LogInformation($"wrote session cookie as \"{userCookie}\" on domain \"{domain}\".");

            // revoke the authflow cookie
            context.Response.Cookies.Delete("authflow");

        }

        protected async Task Redirect(HttpContext context, CasAuthFlow flow)
        {
            if (!string.IsNullOrEmpty(flow.redirecturi))
            {
                context.Response.Redirect(flow.redirecturi);
            }
            await context.Response.CompleteAsync();

        }


    }

}