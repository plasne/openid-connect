using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using System.IdentityModel.Tokens.Jwt;
using Newtonsoft.Json;

namespace CasAuth
{

    public class CasIntAuthenticationOptions : AuthenticationSchemeOptions { }

    public class CasIntAuthenticationHandler : AuthenticationHandler<CasIntAuthenticationOptions>
    {

        public CasIntAuthenticationHandler(
            IOptionsMonitor<CasIntAuthenticationOptions> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            ISystemClock clock)
            : base(options, loggerFactory, encoder, clock)
        {
        }

        private string GetHeaderValue(string name, string dflt = null)
        {
            if (!Request.Headers.ContainsKey(name)) return dflt;
            string value = Request.Headers[name];
            if (string.IsNullOrEmpty(value)) return dflt;
            return value;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            try
            {
                // NOTE: claims.Add(key, value) is an extension method that normalizes the names to their URIs

                // start collecting laims
                var claims = new List<Claim>();

                // extract from bearer token
                string token = GetHeaderValue("Authorization");
                if (!string.IsNullOrEmpty(token))
                {
                    if (token.Contains("Bearer ")) token = token.Split("Bearer ")[1];
                    var handler = new JwtSecurityTokenHandler();
                    var jwt = handler.ReadJwtToken(token);
                    foreach (var claim in jwt.Payload.Claims)
                    {
                        claims.Add(claim.Type, claim.Value);
                    }
                }

                // extract from x-identity
                string xidentity = GetHeaderValue("X-IDENTITY");
                if (!string.IsNullOrEmpty(xidentity))
                {
                    var xidc = JsonConvert.DeserializeObject<Dictionary<string, string>>(xidentity);
                    if (xidc != null && xidc.Count() > 0)
                    {
                        foreach (var claim in xidc)
                        {
                            claims.Add(claim.Key, claim.Value);
                        }
                    }
                }

                // extract from x-email
                string xemail = GetHeaderValue("X-EMAIL");
                if (!string.IsNullOrEmpty(xemail))
                {
                    claims.Add("email", xemail);
                }

                // extract from x-name
                string xname = GetHeaderValue("X-NAME");
                if (!string.IsNullOrEmpty(xname))
                {
                    claims.Add("name", xname);
                }

                // extract from x-roles
                var xroles = Request.Headers["X-ROLES"];
                foreach (var lroles in xroles)
                {
                    var roles = lroles.Split(",").Select(s => s.Trim());
                    foreach (var role in roles)
                    {
                        claims.Add("role", role);
                    }
                }

                // verify there is at least 1 claim
                if (claims.Count() < 1)
                {
                    return Task.FromResult(AuthenticateResult.Fail("no claims for authentication were found"));
                }

                // build the identity, principal, and ticket
                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, Scheme.Name);
                return Task.FromResult(AuthenticateResult.Success(ticket));

            }
            catch (Exception e)
            {
                Logger.LogError(e, "CasIntAuthenticationHandler exception...");
                return Task.FromResult(AuthenticateResult.Fail(e));
            }

        }

    }


    public static class CasIntAuthServicesConfigurationActual
    {

        public static void AddCasIntAuth(this IServiceCollection services)
        {

            // setup authentication
            services
                .AddAuthentication("cas-int")
                .AddScheme<CasIntAuthenticationOptions, CasIntAuthenticationHandler>("cas-int", o => new CasIntAuthenticationOptions());

        }

    }


}