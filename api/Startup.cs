using System;
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
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Linq;
using Microsoft.Extensions.Logging;

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
            Config.Load(factory).Wait();
            Config.Require(new string[] {
                "ISSUER",
                "AUDIENCE",
                "ALLOWED_ORIGINS",
                "PUBLIC_CERTIFICATE_URL",
                "REISSUE_URL"  // enable this to support reissuing tokens
            });
            logger.LogInformation("Configuration loaded.");

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

        private class XsrfRequirement : IAuthorizationRequirement
        {
        }

        private class XsrfHandler : AuthorizationHandler<XsrfRequirement>
        {

            public XsrfHandler(ILoggerFactory loggerFactory)
            {
                this.Logger = loggerFactory.CreateLogger<XsrfHandler>();
            }

            private ILogger Logger { get; }

            protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, XsrfRequirement requirement)
            {
                if (context.Resource is AuthorizationFilterContext mvc)
                {
                    try
                    {
                        var identity = context.User.Identity as ClaimsIdentity;
                        if (identity == null) throw new Exception("identity not found");
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
                return Task.CompletedTask;
            }
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            // add the validator service
            var validator = new TokenValidator(LoggerFactory);
            services.AddSingleton<TokenValidator>(validator);

            // setup authentication
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        RequireExpirationTime = true,
                        RequireSignedTokens = true,
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = TokenValidator.Issuer,
                        ValidAudience = TokenValidator.Audience,
                        IssuerSigningKey = validator.ValidationKey
                    };
                });

            // setup authorization
            services.AddSingleton<IAuthorizationHandler, XsrfHandler>();
            services.AddAuthorization(options =>
            {
                options.AddPolicy("XSRF", policy =>
                {
                    policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(new XsrfRequirement());
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

        public class JwtCookieToHeader
        {

            public JwtCookieToHeader(RequestDelegate next, ILoggerFactory loggerFactory)
            {
                this.Next = next;
                this.Logger = loggerFactory.CreateLogger<JwtCookieToHeader>();
            }

            private RequestDelegate Next { get; }
            private ILogger Logger { get; }

            public async Task Invoke(HttpContext context)
            {
                try
                {

                    // remove any existing authorization header
                    //  note: this ensures someone cannot send something with a madeup xsrf claim
                    context.Request.Headers.Remove("Authorization");

                    // add the authorization header from the user HttpOnly cookie
                    string cookie = context.Request.Cookies["user"];
                    if (!string.IsNullOrEmpty(cookie))
                    {
                        context.Request.Headers.Append("Authorization", "Bearer " + cookie);
                    }

                }
                catch (Exception e)
                {
                    Logger.LogError(e, "exception in JwtCookieToHeader");
                }

                // next
                await Next.Invoke(context);

            }
        }

        public class ReissueToken
        {

            public ReissueToken(RequestDelegate next, ILoggerFactory loggerFactory)
            {
                this.Next = next;
                this.Logger = loggerFactory.CreateLogger<ReissueToken>();
            }

            private RequestDelegate Next { get; }
            private ILogger Logger { get; }

            public async Task Invoke(HttpContext context)
            {
                try
                {

                    // see if the JWT is provided
                    var header = context.Request.Headers["Authorization"];
                    if (header.Count() > 0)
                    {
                        var token = header.First().Replace("Bearer ", "");

                        // see if the token has expired
                        if (TokenValidator.IsTokenExpired(token))
                        {

                            // remove the bad header
                            context.Request.Headers.Remove("Authorization");

                            // attempt to reissue
                            Logger.LogDebug("attempted to reissue an expired token...");
                            try
                            {
                                string reissued = TokenValidator.ReissueToken(token);
                                context.Request.Headers.Append("Authorization", $"Bearer {reissued}");
                                Logger.LogDebug("reissued token successfully");
                            }
                            catch (Exception e)
                            {
                                context.Response.Cookies.Delete("user");
                                Logger.LogError(e, "exception reissuing token, revoked user cookie");
                            }

                        }

                    }

                }
                catch (Exception e)
                {
                    Logger.LogError(e, "exception in ReissueToken");
                }

                // next
                await Next.Invoke(context);

            }
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseCors("origins");
            app.UseMiddleware<JwtCookieToHeader>();
            if (!string.IsNullOrEmpty(TokenValidator.ReissueUrl)) app.UseMiddleware<ReissueToken>();
            //app.UseAuthentication();
            app.UseMvc();
        }
    }
}
