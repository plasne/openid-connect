using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;
using System.Collections.Generic;

namespace dotnetauth
{
    public class Startup
    {
        public Startup(IConfiguration configuration, ILogger<Startup> logger, ILoggerFactory factory)
        {

            // set the logger so it can be used in services
            this.LoggerFactory = factory;

            // load the configuration
            logger.LogInformation("Loading configuration...");
            Config.Apply().Wait();

            // confirm and log the configuration
            logger.LogDebug(Config.Require("ISSUER"));
            logger.LogDebug(Config.Require("AUDIENCE"));
            logger.LogDebug(Config.Require("ALLOWED_ORIGINS"));
            logger.LogDebug(Config.Require("WELL_KNOWN_CONFIG_URL"));
            logger.LogDebug(Config.Require("BASE_DOMAIN"));
            logger.LogDebug(Config.Optional("AUTH_TYPE")); // set to "app" to use an app service principal
            if (AuthChooser.AuthType == "app")
            {
                logger.LogDebug(Config.Require("TENANT_ID"));
                logger.LogDebug(Config.Require("CLIENT_SECRET"));
            }
            logger.LogDebug(Config.Optional("APPCONFIG_RESOURCE_ID")); // use to get settings from Azure App Config
            logger.LogDebug(Config.Optional("CONFIG_KEYS")); // specify the keys to get from Azure App Config

            logger.LogDebug(Config.Optional("REISSUE_URL")); // use to support token reissue
            // PRESENT_CONFIG_?
            logger.LogDebug(Config.Optional("REQUIRE_SECURE_FOR_COOKIES")); // set to "false" if you don't want cookies marked "secure"

        }

        private ILoggerFactory LoggerFactory { get; }

        private static bool AllowAutoRenew
        {
            get
            {
                string ar = System.Environment.GetEnvironmentVariable("ALLOW_AUTO_RENEW");
                if (string.IsNullOrEmpty(ar)) return false;
                return (ar.ToUpper() == "TRUE" || ar.ToUpper() == "YES" || ar == "1");
            }
        }

        private class XsrfRequirement : IAuthorizationRequirement { }

        private class XsrfHandler : AuthorizationHandler<XsrfRequirement>
        {

            public XsrfHandler(ILoggerFactory loggerFactory)
            {
                this.Logger = loggerFactory.CreateLogger<XsrfHandler>();
            }

            private ILogger Logger { get; }

            protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, XsrfRequirement requirement)
            {
                if (TokenValidator.VerifyXsrfHeader)
                {
                    if (context.Resource is AuthorizationFilterContext mvc)
                    {
                        try
                        {
                            var identity = context.User.Identity as ClaimsIdentity;
                            if (identity == null) throw new Exception("identity not found");
                            if (!identity.IsAuthenticated) throw new Exception("user is not authenticated");
                            string token = mvc.HttpContext.Request.Headers["X-XSRF-TOKEN"];
                            if (string.IsNullOrEmpty(token)) throw new Exception("X-XSRF-TOKEN not sent");
                            var claim = identity.FindFirst(c => c.Type == "xsrf");
                            if (claim == null) throw new Exception("xsrf claim not found");
                            if (token != claim.Value) throw new Exception("xsrf claim does not match X-XSRF-TOKEN");
                            context.Succeed(requirement);
                        }
                        catch (Exception e)
                        {
                            Logger.LogError(e, "authorization failure");
                            context.Fail();
                        }
                    }
                    else
                    {
                        Logger.LogError("authorization failure - context.Resource is not AuthorizationFilterContext");
                        context.Fail();
                    }
                }
                else
                {
                    // succeed if XSRF verification isn't required
                    context.Succeed(requirement);
                }
                return Task.CompletedTask;
            }
        }

        public class JwtCookieAuthenticationOptions : AuthenticationSchemeOptions
        {
            public string CookieName { get; set; } = "user";
            public bool AllowAuthorizationHeader { get; set; } = false;
        }

        public class JwtCookieAuthenticationHandler : AuthenticationHandler<JwtCookieAuthenticationOptions>
        {

            public JwtCookieAuthenticationHandler(
                IOptionsMonitor<JwtCookieAuthenticationOptions> options,
                ILoggerFactory logger,
                UrlEncoder encoder,
                ISystemClock clock,
                TokenValidator tokenValidator)
                : base(options, logger, encoder, clock)
            {
                this.TokenValidator = tokenValidator;
            }

            private TokenValidator TokenValidator { get; }

            protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
            {
                bool isTokenFromCookie = false;
                try
                {

                    // check first for header
                    string token = string.Empty;
                    if (Options.AllowAuthorizationHeader)
                    {
                        var header = Request.Headers["Authorization"];
                        if (header.Count() > 0)
                        {
                            token = header.First().Replace("Bearer ", "");
                        }
                    }

                    // look next at the cookie
                    if (string.IsNullOrEmpty(token))
                    {
                        token = Request.Cookies[Options.CookieName];
                        isTokenFromCookie = true;
                    }

                    // shortcut if there is no token
                    if (string.IsNullOrEmpty(token))
                    {
                        Logger.LogDebug("authorization was called, but no token was found");
                        return AuthenticateResult.NoResult();
                    }

                    // see if the token has expired
                    if (TokenValidator.IsTokenExpired(token))
                    {

                        // attempt to reissue
                        Logger.LogDebug("attempted to reissue an expired token...");
                        token = TokenValidator.ReissueToken(token);
                        Logger.LogDebug("reissued token successfully");

                        // rewrite the cookie
                        if (isTokenFromCookie)
                        {
                            Response.Cookies.Append("user", token, new CookieOptions()
                            {
                                HttpOnly = true,
                                Secure = TokenValidator.RequireSecureForCookies,
                                Domain = TokenValidator.BaseDomain,
                                Path = "/"
                            });
                        }

                    }

                    // validate the token
                    var jwt = await this.TokenValidator.ValidateToken(token);

                    // build the identity, principal, and ticket
                    var claims = new List<Claim>();
                    foreach (var claim in jwt.Payload.Claims)
                    {
                        claims.Add(claim);
                        if (claim.Type == "roles") claims.Add(new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", claim.Value));
                    }
                    var identity = new ClaimsIdentity(claims, Scheme.Name);
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

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            // add the validator service
            var validator = new TokenValidator(LoggerFactory);
            services.AddSingleton<TokenValidator>(validator);

            // setup authentication
            services.AddAuthentication("jwt-cookie")
                .AddScheme<JwtCookieAuthenticationOptions, JwtCookieAuthenticationHandler>("jwt-cookie", options =>
                {
                    options.CookieName = "user";
                    options.AllowAuthorizationHeader = TokenValidator.AllowTokenInHeader;
                });

            // setup authorization
            services.AddSingleton<IAuthorizationHandler, XsrfHandler>();
            services.AddAuthorization(options =>
            {
                options.AddPolicy("XSRF", policy =>
                {
                    policy.AddAuthenticationSchemes("jwt-cookie");
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(new XsrfRequirement());

                });
                options.AddPolicy("admin", policy =>
                {
                    policy.AddAuthenticationSchemes("jwt-cookie");
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(new XsrfRequirement());
                    policy.RequireRole("admin");
                });
                options.DefaultPolicy = options.GetPolicy("XSRF");
            });

            // setup CORS policy
            services.AddCors(options =>
               {
                   options.AddPolicy("origins",
                   builder =>
                   {
                       builder.WithOrigins(TokenValidator.AllowedOrigins)
                       .AllowAnyHeader()
                       .AllowAnyMethod()
                       .AllowCredentials();
                   });
               });

            // setup MVC
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseCors("origins");
            app.UseMvc();
        }
    }
}
