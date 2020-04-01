using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace CasAuth
{

    public class CasServerAuthServicesConfiguration
    {
        // this only exists to give the proper ILogger category name
    }

    public static class CasServerAuthServicesConfigurationActual
    {
        public static void AddCasServerAuth(this IServiceCollection services)
        {

            // add HttpClient
            services.AddHttpClient("cas")
                .ConfigurePrimaryHttpMessageHandler(() => new CasProxyHandler());

            // add the configuration service
            services.TryAddSingleton<ICasConfig, CasConfig>();

            // load the configuration and log it
            using (var provider = services.BuildServiceProvider())
            {
                var logger = provider.GetService<ILogger<CasServerAuthServicesConfiguration>>();
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
                config.Require("TENANT_ID", CasEnv.TenantId);
                config.Require("CLIENT_ID", CasEnv.ClientId);
                config.Require("AUTHORITY", CasEnv.Authority);
                config.Require("REDIRECT_URI", CasEnv.RedirectUri);
                config.Require("ISSUER", CasEnv.Issuer);
                config.Require("AUDIENCE", CasEnv.Audience);
                config.Require("DEFAULT_REDIRECT_URL", CasEnv.DefaultRedirectUrl);
                config.Require("ALLOWED_ORIGINS", CasEnv.AllowedOrigins);
                config.Require("BASE_DOMAIN", CasEnv.BaseDomain);
                config.Require("PUBLIC_KEYS_URL", CasEnv.PublicKeysUrl);
                config.Require("PRIVATE_KEY", CasEnv.PrivateKey);
                config.Require("PRIVATE_KEY_PASSWORD", CasEnv.PrivateKeyPassword);
                config.Require("PUBLIC_CERT_0", CasEnv.PublicCert0);
                config.Optional("PUBLIC_CERT_1", CasEnv.PublicCert1);
                config.Optional("PUBLIC_CERT_2", CasEnv.PublicCert2);
                config.Optional("PUBLIC_CERT_3", CasEnv.PublicCert3);
                config.Optional("AUTH_TYPE", authType);
                if (authType == "app")
                {
                    config.Require("CLIENT_SECRET", CasEnv.ClientSecret);
                }
                else
                {
                    // required for authcode
                    config.Optional("CLIENT_SECRET", CasEnv.ClientSecret);
                }
                config.Optional("AUTH_TYPE_CONFIG", CasAuthChooser.AuthType("AUTH_TYPE_CONFIG"));
                config.Optional("AUTH_TYPE_VAULT", CasAuthChooser.AuthType("AUTH_TYPE_VAULT"));
                config.Optional("AUTH_TYPE_GRAPH", CasAuthChooser.AuthType("AUTH_TYPE_GRAPH"));
                config.Optional("APPCONFIG", CasEnv.AppConfig);
                config.Optional("CONFIG_KEYS", CasEnv.ConfigKeys);
                config.Optional("APPLICATION_ID", CasEnv.ApplicationIds);
                config.Optional("REQUIRE_SECURE_FOR_COOKIES", CasEnv.RequireSecureForCookies, hideValue: false);
                config.Optional("REQUIRE_USER_ENABLED_ON_REISSUE", CasEnv.RequireUserEnabledOnReissue, hideValue: false);
                config.Optional("REQUIRE_HTTPONLY_ON_USER_COOKIE", CasEnv.RequireHttpOnlyOnUserCookie, hideValue: false);
                config.Optional("REQUIRE_HTTPONLY_ON_XSRF_COOKIE", CasEnv.RequireHttpOnlyOnXsrfCookie, hideValue: false);
                config.Optional("VERIFY_XSRF_IN_HEADER", CasEnv.VerifyXsrfInHeader, hideValue: false);
                config.Optional("VERIFY_XSRF_IN_COOKIE", CasEnv.VerifyXsrfInCookie, hideValue: false);

            }

            // add the issuer service
            services.AddSingleton<CasTokenIssuer, CasTokenIssuer>();

            // setup CORS policy
            if (CasEnv.AllowedOrigins.Length > 0)
            {
                services.AddCors(options =>
                   {
                       options.AddPolicy("cas-server", builder =>
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