using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using NetBricks;

namespace CasAuth
{

    public class CasClientAuthServicesConfiguration
    {
        // this only exists to give the proper ILogger category name
    }

    public static class CasClientAuthServicesConfigurationActual
    {

        public static async Task AddCasClientAuthAsync(this IServiceCollection services)
        {

            // add the logger
            services.AddSingleLineConsoleLogger();

            // add the HttpContext
            services.AddHttpContextAccessor();

            // add HttpClients
            services.AddHttpClient("netbricks")
                .ConfigurePrimaryHttpMessageHandler(() => new CasProxyHandler());
            services.AddHttpClient("cas")
                .ConfigurePrimaryHttpMessageHandler(() => new CasProxyHandler());

            // add the access token fetcher
            services.AddAccessTokenFetcher();

            // add the configuration service
            services.TryAddSingleton<IConfig, CasConfig>();

            // load the configuration and log it
            using (var provider = services.BuildServiceProvider())
            {
                var logger = provider.GetService<ILogger<CasClientAuthServicesConfiguration>>();

                // get the config
                var config = provider.GetService<IConfig>() as CasConfig;
                if (config == null) throw new Exception("AddCasClientAuth: CasConfig could not be found in the IServiceCollection.");

                // determine the authentication type
                var authType = config.AuthType();
                if (authType == AuthTypes.Service) logger.LogInformation("authentication: application ClientId and ClientSecret (service principal).");
                if (authType == AuthTypes.Token) logger.LogInformation("authentication: managed identity with failback to az cli.");

                // load the configuration
                logger.LogInformation("Loading configuration...");
                await config.Apply();

                // confirm and log the configuration
                config.Optional("AUTH_TYPE", authType.ToString());
                config.Optional("AUTH_TYPE_CONFIG", config.AuthType("CONFIG").ToString());
                if (authType == AuthTypes.Service)
                {
                    config.Require("AZURE_TENANT_ID", CasConfig.AzureTenantId);
                    config.Require("AZURE_CLIENT_ID", CasConfig.AzureClientId);
                    config.Require("AZURE_CLIENT_SECRET", await config.AzureClientSecret(), hideValue: true);
                }
                config.Optional("APPCONFIG", CasConfig.AppConfig, hideIfEmpty: true);
                config.Optional("CONFIG_KEYS", CasConfig.ConfigKeys, hideIfEmpty: true);
                config.Optional("PROXY", CasConfig.Proxy, hideIfEmpty: true);
                config.Optional("DEFAULT_HOST_URL", CasConfig.DefaultHostUrl, hideIfEmpty: true);
                config.Optional("SERVER_HOST_URL", CasConfig.ServerHostUrl);
                config.Optional("CLIENT_HOST_URL", CasConfig.ClientHostUrl);
                config.Optional("WEB_HOST_URL", CasConfig.WebHostUrl);
                config.Optional("USE_INSECURE_DEFAULTS", CasConfig.UseInsecureDefaults, hideValue: false);
                config.Optional("IS_HTTPS", CasConfig.IsHttps, hideValue: false);
                config.Require("ISSUER", CasConfig.Issuer);
                config.Require("AUDIENCE", CasConfig.Audience);
                config.Require("ALLOWED_ORIGINS", CasConfig.AllowedOrigins);
                config.Require("BASE_DOMAIN", CasConfig.BaseDomain());
                config.Require("WELL_KNOWN_CONFIG_URL", CasConfig.WellKnownConfigUrl);
                config.Optional("REQUIRE_SECURE_FOR_COOKIES", CasConfig.RequireSecureForCookies, hideValue: false);
                config.Optional("REQUIRE_HTTPONLY_ON_USER_COOKIE", CasConfig.RequireHttpOnlyOnUserCookie, hideValue: false);
                config.Optional("REQUIRE_HTTPONLY_ON_XSRF_COOKIE", CasConfig.RequireHttpOnlyOnXsrfCookie, hideValue: false);
                config.Optional("VERIFY_TOKEN_IN_HEADER", CasConfig.VerifyTokenInHeader, hideValue: false);
                config.Optional("VERIFY_TOKEN_IN_COOKIE", CasConfig.VerifyTokenInCookie, hideValue: false);
                config.Optional("VERIFY_XSRF_IN_HEADER", CasConfig.VerifyXsrfInHeader, hideValue: false);
                config.Optional("VERIFY_XSRF_IN_COOKIE", CasConfig.VerifyXsrfInCookie, hideValue: false);
                config.Optional("SAME_SITE", CasConfig.SameSite.ToString());
                config.Optional("USER_COOKIE_NAME", CasConfig.UserCookieName);
                config.Optional("ROLE_FOR_ADMIN", CasConfig.RoleForAdmin);
                config.Optional("ROLE_FOR_SERVICE", CasConfig.RoleForService);

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
            if (CasConfig.AllowedOrigins?.Length > 0)
            {
                services.AddCors(options =>
                   {
                       options.AddPolicy("cas-client", builder =>
                       {
                           builder.WithOrigins(CasConfig.AllowedOrigins)
                           .AllowAnyHeader()
                           .AllowAnyMethod()
                           .AllowCredentials();
                       });
                   });
            }

        }

        public static void AddCasClientAuth(this IServiceCollection services)
        {
            AddCasClientAuthAsync(services).Wait();
        }
    }

}