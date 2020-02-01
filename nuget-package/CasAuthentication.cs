using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CasAuth
{

    public class CasAuthenticationOptions : AuthenticationSchemeOptions { }

    public class CasAuthenticationHandler : AuthenticationHandler<CasAuthenticationOptions>
    {

        public CasAuthenticationHandler(
            IOptionsMonitor<CasAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            CasTokenValidator tokenValidator)
            : base(options, logger, encoder, clock)
        {
            this.CasTokenValidator = tokenValidator;
        }

        private CasTokenValidator CasTokenValidator { get; }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            bool isTokenFromHeader = false;
            bool isTokenFromCookie = false;
            try
            {

                // check first for header
                string token = string.Empty;
                var header = Request.Headers["Authorization"];
                if (header.Count() > 0)
                {
                    token = header.First().Replace("Bearer ", "");
                    isTokenFromHeader = true;
                }

                // look next at the cookie
                if (CasEnv.VerifyTokenInCookie && string.IsNullOrEmpty(token))
                {
                    token = Request.Cookies[CasEnv.UserCookieName];
                    isTokenFromCookie = true;
                }

                // shortcut if there is no token
                if (string.IsNullOrEmpty(token))
                {
                    Logger.LogDebug("authorization was called, but no token was found");
                    return AuthenticateResult.NoResult();
                }

                // see if the token has expired
                if (CasTokenValidator.IsTokenExpired(token))
                {

                    // attempt to reissue
                    Logger.LogDebug("attempted to reissue an expired token...");
                    var httpClientFactory = Request.HttpContext.RequestServices.GetService(typeof(IHttpClientFactory)) as IHttpClientFactory;
                    var httpClient = httpClientFactory.CreateClient("cas");
                    token = await CasTokenValidator.ReissueToken(httpClient, token);
                    Logger.LogDebug("reissued token successfully");

                    // rewrite the cookie
                    if (isTokenFromCookie)
                    {
                        Response.Cookies.Append(CasEnv.UserCookieName, token, new CookieOptions()
                        {
                            HttpOnly = CasEnv.RequireHttpOnlyOnUserCookie,
                            Secure = CasEnv.RequireSecureForCookies,
                            Domain = CasEnv.BaseDomain,
                            Path = "/"
                        });
                    }

                }

                // validate the token
                var jwt = await this.CasTokenValidator.ValidateToken(token);

                // if the token was in the header and that wasn't allowed, it had better be a service account
                if (isTokenFromHeader &&
                    !CasEnv.VerifyTokenInHeader &&
                    !jwt.Payload.Claims.IsService()
                )
                {
                    throw new Exception("only service account types are allowed in the header");
                }

                // propogate the claims and dedupe
                var claims = new List<Claim>();
                foreach (var claim in jwt.Payload.Claims)
                {
                    claims.Add(claim.Type, claim.Value);
                }
                var dedupe = claims.Distinct();

                // build the identity, principal, and ticket
                var identity = new ClaimsIdentity(dedupe, Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, Scheme.Name);
                return AuthenticateResult.Success(ticket);

            }
            catch (Exception e)
            {
                Logger.LogError(e, "JwtCookieAuthenticationHandler exception");
                if (isTokenFromCookie) Response.Cookies.Delete("user"); // revoke the cookie
                return AuthenticateResult.Fail(e);
            }

        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.Headers["WWW-Authenticate"] = $"Cookie realm=\"auth\", charset=\"UTF-8\"";
            await base.HandleChallengeAsync(properties);
        }
    }

}