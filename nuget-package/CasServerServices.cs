using System;
using System.Net;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
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
                .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler()
                {
                    Proxy = (!string.IsNullOrEmpty(CasEnv.Proxy)) ? new WebProxy(CasEnv.Proxy, true) : null,
                    UseProxy = (!string.IsNullOrEmpty(CasEnv.Proxy))
                });

            // load the configuration and log it
            using (var provider = services.BuildServiceProvider())
            {
                var logger = provider.GetService<ILogger<CasServerAuthServicesConfiguration>>();

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
                CasConfig.Require("SERVER_HOST_URL", CasEnv.ServerHostUrl, logger);
                CasConfig.Optional("CLIENT_HOST_URL", CasEnv.ClientHostUrl, logger);
                CasConfig.Require("TENANT_ID", CasEnv.TenantId, logger);
                CasConfig.Require("AUTHORITY", CasEnv.Authority, logger);
                CasConfig.Require("REDIRECT_URI", CasEnv.RedirectUri, logger);
                CasConfig.Require("ISSUER", CasEnv.Issuer, logger);
                CasConfig.Require("AUDIENCE", CasEnv.Audience, logger);
                CasConfig.Require("DEFAULT_REDIRECT_URL", CasEnv.DefaultRedirectUrl, logger);
                CasConfig.Require("ALLOWED_ORIGINS", CasEnv.AllowedOrigins, logger);
                CasConfig.Require("BASE_DOMAIN", CasEnv.BaseDomain, logger);
                CasConfig.Require("CLIENT_ID", CasEnv.ClientId, logger);
                CasConfig.Require("PUBLIC_KEYS_URL", CasEnv.PublicKeysUrl, logger);
                if (
                    !CasConfig.Optional("PRIVATE_KEY", CasEnv.PrivateKey, logger) &&
                    !CasConfig.Optional("KEYVAULT_PRIVATE_KEY_URL", CasEnv.KeyvaultPrivateKeyUrl, logger)
                )
                {
                    logger.LogError("You must specify either PRIVATE_KEY or KEYVAULT_PRIVATE_KEY_URL.");
                    throw new Exception("You must specify either PRIVATE_KEY or KEYVAULT_PRIVATE_KEY_URL.");
                }
                if (
                    !CasConfig.Optional("PRIVATE_KEY_PASSWORD", CasEnv.PrivateKeyPassword, logger) &&
                    !CasConfig.Optional("KEYVAULT_PRIVATE_KEY_PASSWORD_URL", CasEnv.KeyvaultPrivateKeyPasswordUrl, logger)
                )
                {
                    logger.LogError("You must specify either PRIVATE_KEY_PASSWORD or KEYVAULT_PRIVATE_KEY_PASSWORD_URL.");
                    throw new Exception("You must specify either PRIVATE_KEY_PASSWORD or KEYVAULT_PRIVATE_KEY_PASSWORD_URL.");
                }
                if (
                    !CasConfig.Optional("PUBLIC_CERT_0", CasEnv.PublicCertificates, logger) &&
                    !CasConfig.Optional("PUBLIC_CERT_1", CasEnv.PublicCertificates, logger) &&
                    !CasConfig.Optional("PUBLIC_CERT_2", CasEnv.PublicCertificates, logger) &&
                    !CasConfig.Optional("PUBLIC_CERT_3", CasEnv.PublicCertificates, logger) &&
                    !CasConfig.Optional("KEYVAULT_PUBLIC_CERT_PREFIX_URL", CasEnv.KeyvaultPublicCertificateUrls, logger)
                )
                {
                    logger.LogError("You must specify one of PUBLIC_CERT_0, PUBLIC_CERT_1, PUBLIC_CERT_2, PUBLIC_CERT_3, or KEYVAULT_PUBLIC_CERT_PREFIX_URL.");
                    throw new Exception("You must specify one of PUBLIC_CERT_0, PUBLIC_CERT_1, PUBLIC_CERT_2, PUBLIC_CERT_3, or KEYVAULT_PUBLIC_CERT_PREFIX_URL.");
                }
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
                CasConfig.Optional("AUTH_TYPE_VAULT", CasAuthChooser.AuthType("AUTH_TYPE_VAULT"), logger);
                CasConfig.Optional("AUTH_TYPE_GRAPH", CasAuthChooser.AuthType("AUTH_TYPE_GRAPH"), logger);
                CasConfig.Optional("APPCONFIG_RESOURCE_ID", CasConfig.AppConfigResourceId, logger);
                CasConfig.Optional("CONFIG_KEYS", CasConfig.ConfigKeys, logger);
                CasConfig.Optional("APPLICATION_ID", CasEnv.ApplicationIds, logger);
                CasConfig.Optional("REQUIRE_SECURE_FOR_COOKIES", CasEnv.RequireSecureForCookies, logger);
                CasConfig.Optional("REQUIRE_USER_ENABLED_ON_REISSUE", CasEnv.RequireUserEnabledOnReissue, logger);
                CasConfig.Optional("REQUIRE_HTTPONLY_ON_USER_COOKIE", CasEnv.RequireHttpOnlyOnUserCookie, logger);
                CasConfig.Optional("REQUIRE_HTTPONLY_ON_XSRF_COOKIE", CasEnv.RequireHttpOnlyOnXsrfCookie, logger);
                CasConfig.Optional("VERIFY_XSRF_IN_HEADER", CasEnv.VerifyXsrfInHeader, logger);
                CasConfig.Optional("VERIFY_XSRF_IN_COOKIE", CasEnv.VerifyXsrfInCookie, logger);

            }

            // add the issuer service
            services.AddSingleton<CasTokenIssuer, CasTokenIssuer>();

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