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

namespace authproxy
{

    public class JwtAuthenticationOptions : AuthenticationSchemeOptions { }

    public class JwtAuthenticationHandler : AuthenticationHandler<JwtAuthenticationOptions>
    {

        public JwtAuthenticationHandler(
            IOptionsMonitor<JwtAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            TokenValidator tokenValidator
        ) : base(options, logger, encoder, clock)
        {
            this.TokenValidator = tokenValidator;
        }

        private TokenValidator TokenValidator { get; }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            bool isTokenFromCookie = false;
            try
            {
                Logger.LogDebug("HandleAuthenticateAsync: started authentication check...");
                string token = string.Empty;

                // check first for header
                if (!string.IsNullOrEmpty(Program.JwtHeader))
                {
                    var header = Request.Headers["Authorization"];
                    if (header.Count() > 0)
                    {
                        Logger.LogDebug($"HandleAuthenticateAsync: checking header named \"Authorization\" for token...");
                        token = header.First().Replace("Bearer ", "");
                    }
                }

                // look next at the cookie
                if (!string.IsNullOrEmpty(Program.JwtCookie))
                {
                    Logger.LogDebug($"HandleAuthenticateAsync: checking cookie named \"{Program.JwtCookie}\" for token...");
                    token = Request.Cookies[Program.JwtCookie];
                    isTokenFromCookie = true;
                }

                // shortcut if there is no token
                if (string.IsNullOrEmpty(token))
                {
                    Logger.LogDebug("HandleAuthenticateAsync: no token was found.");
                    return AuthenticateResult.NoResult();
                }

                // validate the token
                var jwt = await TokenValidator.ValidateToken(token);

                // propogate the claims (this overload uses uri-names and dedupes)
                var claims = new List<Claim>();
                foreach (var claim in jwt.Payload.Claims)
                {
                    claims.AddLong(claim.Type, claim.Value);
                }

                // build the identity, principal, and ticket
                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, Scheme.Name);
                return AuthenticateResult.Success(ticket);

            }
            catch (Exception e)
            {
                Logger.LogWarning(e, "HandleAuthenticateAsync: exception...");
                if (isTokenFromCookie) Response.Cookies.Delete(Program.JwtCookie); // revoke the cookie
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