using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace CasAuth
{

    public class CasClientAuthServicesConfiguration
    {
        // this only exists to give the proper ILogger category name
    }

    public static class CasClientAuthServicesConfigurationActual
    {
        public static void AddCasClientAuth(this IServiceCollection services)
        {

            // add the HttpContext
            services.AddHttpContextAccessor();

            // add HttpClient
            services.AddHttpClient("cas")
                .ConfigurePrimaryHttpMessageHandler(() => new CasProxyHandler());

            // add the configuration service
            services.TryAddSingleton<ICasConfig, CasConfig>();

            // load the configuration and log it
            using (var provider = services.BuildServiceProvider())
            {
                var logger = provider.GetService<ILogger<CasClientAuthServicesConfiguration>>();
                var config = provider.GetService<ICasConfig>();

                // determine the authentication type
                string authType = CasAuthChooser.AuthType();
                if (authType == "app") logger.LogInformation("authentication: application ClientId and ClientSecret (service principal).");
                if (authType == "mi") logger.LogInformation("authentication: managed identity with failback to az cli.");

                // load the configuration
                logger.LogInformation("Loading configuration...");
                config.Apply().Wait();

                // confirm and log the configuration
                config.Optional("SERVER_HOST_URL", CasEnv.ServerHostUrl);
                config.Optional("CLIENT_HOST_URL", CasEnv.ClientHostUrl);
                config.Optional("WEB_HOST_URL", CasEnv.WebHostUrl);
                config.Require("ISSUER", CasEnv.Issuer);
                config.Require("AUDIENCE", CasEnv.Audience);
                config.Require("ALLOWED_ORIGINS", CasEnv.AllowedOrigins);
                config.Require("WELL_KNOWN_CONFIG_URL", CasEnv.WellKnownConfigUrl);
                config.Require("BASE_DOMAIN", CasEnv.BaseDomain());
                config.Optional("AUTH_TYPE", authType);
                if (authType == "app")
                {
                    config.Require("TENANT_ID", CasEnv.AzureTenantId);
                    config.Require("CLIENT_ID", CasEnv.AzureClientId);
                    config.Require("CLIENT_SECRET", CasEnv.AzureClientSecret);
                }
                config.Optional("AUTH_TYPE_CONFIG", CasAuthChooser.AuthType("AUTH_TYPE_CONFIG"));
                config.Optional("APPCONFIG", CasEnv.AppConfig);
                config.Optional("CONFIG_KEYS", CasEnv.ConfigKeys);
                config.Optional("REQUIRE_SECURE_FOR_COOKIES", CasEnv.RequireSecureForCookies, hideValue: false);
                config.Optional("REQUIRE_HTTPONLY_ON_USER_COOKIE", CasEnv.RequireHttpOnlyOnUserCookie, hideValue: false);
                config.Optional("REQUIRE_HTTPONLY_ON_XSRF_COOKIE", CasEnv.RequireHttpOnlyOnXsrfCookie, hideValue: false);
                config.Optional("VERIFY_TOKEN_IN_HEADER", CasEnv.VerifyTokenInHeader, hideValue: false);
                config.Optional("VERIFY_TOKEN_IN_COOKIE", CasEnv.VerifyTokenInCookie, hideValue: false);
                config.Optional("VERIFY_XSRF_IN_HEADER", CasEnv.VerifyXsrfInHeader, hideValue: false);
                config.Optional("VERIFY_XSRF_IN_COOKIE", CasEnv.VerifyXsrfInCookie, hideValue: false);
                config.Optional("USER_COOKIE_NAME", CasEnv.UserCookieName);

            }

            // add the validator service
            services.AddSingleton<CasTokenValidator>();

            // setup authentication
            services
                .AddAuthentication("cas")
                .AddScheme<CasAuthenticationOptions, CasAuthenticationHandler>("cas", o => new CasAuthenticationOptions());

            // setup authorization
            services.AddSingleton<IAuthorizationHandler, CasXsrfHandler>();
            services.AddAuthorization(options =>
            {
                options.AddPolicy("cas", policy =>
                {
                    policy.AddAuthenticationSchemes("cas");
                    policy.RequireAuthenticatedUser();
                    policy.Requirements.Add(new CasXsrfRequirement());
                });
                options.AddPolicy("cas-no-xsrf", policy =>
                {
                    policy.AddAuthenticationSchemes("cas");
                    policy.RequireAuthenticatedUser();
                });
                options.DefaultPolicy = options.GetPolicy("cas");
            });

            // setup CORS policy
            if (CasEnv.AllowedOrigins.Length > 0)
            {
                services.AddCors(options =>
                   {
                       options.AddPolicy("cas-client", builder =>
                       {
                           builder.WithOrigins(CasEnv.AllowedOrigins)
                           .AllowAnyHeader()
                           .AllowAnyMethod()
                           .AllowCredentials();
                       });
                   });
            }

        }
    }

}