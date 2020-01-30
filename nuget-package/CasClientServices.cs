using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
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
                .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler()
                {
                    Proxy = (!string.IsNullOrEmpty(CasEnv.Proxy)) ? new WebProxy(CasEnv.Proxy, true) : null,
                    UseProxy = (!string.IsNullOrEmpty(CasEnv.Proxy))
                });

            // load the configuration and log it
            using (var provider = services.BuildServiceProvider())
            {
                var logger = provider.GetService<ILogger<CasClientAuthServicesConfiguration>>();

                // determine the authentication type
                string authType = CasAuthChooser.AuthType();
                if (authType == "app") logger.LogInformation("authentication: application ClientId and ClientSecret (service principal).");
                if (authType == "mi") logger.LogInformation("authentication: managed identity with failback to az cli.");

                // load the configuration
                logger.LogInformation("Loading configuration...");
                var httpClientFactory = provider.GetService<IHttpClientFactory>();
                var httpClient = httpClientFactory.CreateClient("cas");
                CasConfig.Apply(httpClient).Wait();

                // confirm and log the configuration
                CasConfig.Require("CLIENT_HOST_URL", CasEnv.ClientHostUrl, logger);
                CasConfig.Require("ISSUER", CasEnv.Issuer, logger);
                CasConfig.Require("AUDIENCE", CasEnv.Audience, logger);
                CasConfig.Require("ALLOWED_ORIGINS", CasEnv.AllowedOrigins, logger);
                CasConfig.Require("WELL_KNOWN_CONFIG_URL", CasEnv.WellKnownConfigUrl, logger);
                CasConfig.Require("BASE_DOMAIN", CasEnv.BaseDomain, logger);
                CasConfig.Optional("AUTH_TYPE", authType, logger);
                if (authType == "app")
                {
                    CasConfig.Require("TENANT_ID", CasEnv.TenantId, logger);
                    CasConfig.Require("CLIENT_SECRET", CasEnv.ClientSecret, logger);
                }
                else
                {
                    // NOTE: a secret is needed for authcode
                    CasConfig.Optional("CLIENT_SECRET", CasEnv.ClientSecret, logger);
                    CasConfig.Optional("KEYVAULT_CLIENT_SECRET_URL", CasEnv.KeyvaultClientSecretUrl, logger);
                }
                CasConfig.Optional("AUTH_TYPE_CONFIG", CasAuthChooser.AuthType("AUTH_TYPE_CONFIG"), logger);
                CasConfig.Optional("APPCONFIG_RESOURCE_ID", CasConfig.AppConfigResourceId, logger);
                CasConfig.Optional("CONFIG_KEYS", CasConfig.ConfigKeys, logger);
                CasConfig.Optional("REQUIRE_SECURE_FOR_COOKIES", CasEnv.RequireSecureForCookies, logger);
                CasConfig.Optional("REQUIRE_HTTPONLY_ON_USER_COOKIE", CasEnv.RequireHttpOnlyOnUserCookie, logger);
                CasConfig.Optional("REQUIRE_HTTPONLY_ON_XSRF_COOKIE", CasEnv.RequireHttpOnlyOnXsrfCookie, logger);
                CasConfig.Optional("VERIFY_TOKEN_IN_HEADER", CasEnv.VerifyTokenInHeader, logger);
                CasConfig.Optional("VERIFY_TOKEN_IN_COOKIE", CasEnv.VerifyTokenInCookie, logger);
                CasConfig.Optional("VERIFY_XSRF_IN_HEADER", CasEnv.VerifyXsrfInHeader, logger);
                CasConfig.Optional("VERIFY_XSRF_IN_COOKIE", CasEnv.VerifyXsrfInCookie, logger);
                CasConfig.Optional("USER_COOKIE_NAME", CasEnv.UserCookieName, logger);

            }

            // add the validator service
            services.AddSingleton<CasTokenValidator, CasTokenValidator>();

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
                options.DefaultPolicy = options.GetPolicy("cas");
            });

            // setup CORS policy
            if (CasEnv.AllowedOrigins.Length > 0)
            {
                services.AddCors(options =>
                   {
                       options.AddDefaultPolicy(builder =>
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