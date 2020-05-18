using System;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace authproxy
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {

            // add HttpContextAccessor
            services.AddHttpContextAccessor();

            // add HttpClient
            services.AddHttpClient("authproxy");

            // add the console logger
            services.AddSingleLineConsoleLogger();

            // add the token validator
            services.AddSingleton<TokenValidator>();

            // setup authentication
            services
                .AddAuthentication("authproxy")
                .AddScheme<JwtAuthenticationOptions, JwtAuthenticationHandler>("authproxy", o => new JwtAuthenticationOptions());

            // setup authorization
            services.AddSingleton<IAuthorizationHandler, XsrfHandler>();
            services.AddAuthorization(options =>
            {
                options.AddPolicy("authproxy", policy =>
                {
                    policy.AddAuthenticationSchemes("authproxy");
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(new XsrfRequirement());
                });
            });

        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IServiceProvider provider)
        {
            var logger = provider.GetService<ILogger<Startup>>();

            // check for required variables
            logger.LogInformation($"FROM_PORT = \"{Program.FromPort}\"");
            logger.LogInformation($"TO_PORT = \"{Program.ToPort}\"");
            logger.LogInformation($"TO_HOST = \"{Program.ToHost}\"");
            logger.LogInformation($"ALLOW_ANONYMOUS = \"{Program.AllowAnonymous}\"");
            logger.LogInformation($"JWT_HEADER = \"{Program.JwtHeader}\"");
            logger.LogInformation($"JWT_COOKIE = \"{Program.JwtCookie}\"");
            logger.LogInformation($"XSRF_HEADER = \"{Program.XsrfHeader}\"");
            logger.LogInformation($"XSRF_CLAIM = \"{Program.XsrfClaim}\"");
            logger.LogInformation($"WELL_KNOWN_CONFIG_URL = \"{Program.WellKnownConfigUrl}\"");
            logger.LogInformation($"ISSUER = \"{string.Join(", ", Program.Issuer)}\"");
            logger.LogInformation($"AUDIENCE = \"{string.Join(", ", Program.Audience)}\"");

            // add authentication and authorization if appropriate
            if (Program.AllowAnonymous)
            {
                logger.LogInformation("authentication and authorization will be IGNORED before passing on a check.");
            }
            else
            {

                // check requirements for authentication, authorization to work
                if (string.IsNullOrEmpty(Program.JwtHeader) && string.IsNullOrEmpty(Program.JwtCookie))
                {
                    throw new Exception("you must specify JWT_HEADER and/or JWT_COOKIE for authentication to work.");
                }
                if (string.IsNullOrEmpty(Program.XsrfHeader) != string.IsNullOrEmpty(Program.XsrfClaim))
                {
                    throw new Exception("you must either specify both XSRF_HEADER and XSRF_CLAIM or neither.");
                }
                if (!string.IsNullOrEmpty(Program.JwtHeader) && !string.IsNullOrEmpty(Program.XsrfHeader))
                {
                    throw new Exception("it is not helpful to accept both JWT_HEADER and XSRF_HEADER");
                }
                if (string.IsNullOrEmpty(Program.WellKnownConfigUrl))
                {
                    throw new Exception("you must specify a valid URL for WELL_KNOWN_CONFIG_URL.");
                }

                // add authN and authZ
                app.UseAuthentication();
                app.UseMiddleware<AuthorizationMiddleware>("authproxy");
                logger.LogInformation("authentication and authorization will be VERIFIED before passing on a check.");

            }

            // add the reverse proxy
            app.UseMiddleware<ReverseProxyMiddleware>();

        }

    }
}
