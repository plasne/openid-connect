using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using NetBricks;

namespace CasAuth
{

    public class CasServerAuthServicesConfiguration
    {
        // this only exists to give the proper ILogger category name
    }

    public static class CasServerAuthServicesConfigurationActual
    {

        public static async Task AddCasServerAuthAsync(this IServiceCollection services)
        {

            // add the logger
            services.AddSingleLineConsoleLogger();

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
                var logger = provider.GetService<ILogger<CasServerAuthServicesConfiguration>>();
                var authCodeReceiver = provider.GetService<ICasAuthCodeReceiver>();

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
                config.Optional("AUTH_TYPE_VAULT", config.AuthType("VAULT").ToString());
                config.Optional("AUTH_TYPE_GRAPH", config.AuthType("GRAPH").ToString());
                config.Require("AZURE_TENANT_ID", CasConfig.AzureTenantId);
                config.Require("AZURE_CLIENT_ID", CasConfig.AzureClientId);
                if (authType == AuthTypes.Service || authCodeReceiver != null)
                {
                    config.Require("AZURE_CLIENT_SECRET", await config.AzureClientSecret(), hideValue: true);
                }
                else
                {
                    config.Optional("AZURE_CLIENT_SECRET", await config.AzureClientSecret(), hideValue: true);
                }
                config.Optional("APPCONFIG", CasConfig.AppConfig, hideIfEmpty: true);
                config.Optional("CONFIG_KEYS", CasConfig.ConfigKeys, hideIfEmpty: true);
                config.Optional("PROXY", CasConfig.Proxy, hideIfEmpty: true);
                config.Optional("DEFAULT_HOST_URL", CasConfig.DefaultHostUrl, hideIfEmpty: true);
                config.Optional("SERVER_HOST_URL", CasConfig.ServerHostUrl, hideIfEmpty: true);
                config.Optional("CLIENT_HOST_URL", CasConfig.ClientHostUrl, hideIfEmpty: true);
                config.Optional("WEB_HOST_URL", CasConfig.WebHostUrl, hideIfEmpty: true);
                config.Optional("USE_INSECURE_DEFAULTS", CasConfig.UseInsecureDefaults, hideValue: false);
                config.Optional("IS_HTTPS", CasConfig.IsHttps, hideValue: false);
                config.Require("AZURE_AUTHORITY", CasConfig.AzureAuthority);
                config.Optional("GOOGLE_CLIENT_ID", CasConfig.GoogleClientId);
                config.Require("REDIRECT_URI", CasConfig.RedirectUri());
                config.Require("ISSUER", CasConfig.Issuer);
                config.Require("AUDIENCE", CasConfig.Audience);
                config.Require("ALLOWED_ORIGINS", CasConfig.AllowedOrigins);
                config.Require("BASE_DOMAIN", CasConfig.BaseDomain());
                config.Require("PUBLIC_KEYS_URL", CasConfig.PublicKeysUrl);
                config.Require("PRIVATE_KEY", await config.PrivateKey(), hideValue: true);
                config.Require("PRIVATE_KEY_PASSWORD", await config.PrivateKeyPassword(), hideValue: true);
                config.Require("PUBLIC_CERT_0", await config.PublicCert(0), hideValue: true);
                config.Optional("PUBLIC_CERT_1", await config.PublicCert(1), hideValue: true, hideIfEmpty: true);
                config.Optional("PUBLIC_CERT_2", await config.PublicCert(2), hideValue: true, hideIfEmpty: true);
                config.Optional("PUBLIC_CERT_3", await config.PublicCert(3), hideValue: true, hideIfEmpty: true);
                config.Optional("DEFAULT_REDIRECT_URL", CasConfig.DefaultRedirectUrl);
                config.Optional("AZURE_APPLICATION_ID", CasConfig.AzureApplicationIds, hideIfEmpty: true);
                config.Optional("REQUIRE_SECURE_FOR_COOKIES", CasConfig.RequireSecureForCookies, hideValue: false);
                config.Optional("REQUIRE_USER_ENABLED_ON_REISSUE", CasConfig.RequireUserEnabledOnReissue, hideValue: false);
                config.Optional("REQUIRE_HTTPONLY_ON_USER_COOKIE", CasConfig.RequireHttpOnlyOnUserCookie, hideValue: false);
                config.Optional("REQUIRE_HTTPONLY_ON_XSRF_COOKIE", CasConfig.RequireHttpOnlyOnXsrfCookie, hideValue: false);
                config.Optional("VERIFY_XSRF_IN_HEADER", CasConfig.VerifyXsrfInHeader, hideValue: false);
                config.Optional("VERIFY_XSRF_IN_COOKIE", CasConfig.VerifyXsrfInCookie, hideValue: false);
                config.Optional("SAME_SITE", CasConfig.SameSite.ToString());
                config.Optional("USER_COOKIE_NAME", CasConfig.UserCookieName);
                config.Optional("ROLE_FOR_ADMIN", CasConfig.RoleForAdmin);
                config.Optional("ROLE_FOR_SERVICE", CasConfig.RoleForService);
                config.Optional("AZURE_DOMAIN_HINT", CasConfig.AzureDomainHint, hideIfEmpty: true);
                config.Optional("GOOGLE_DOMAIN_HINT", CasConfig.GoogleDomainHint, hideIfEmpty: true);
                config.Optional("GOOGLE_EMAIL_MUST_BE_VERIFIED", CasConfig.GoogleEmailMustBeVerified, hideValue: false);
                config.Optional("JWT_DURATION", CasConfig.JwtDuration.ToString());
                config.Optional("JWT_SERVICE_DURATION", CasConfig.JwtServiceDuration.ToString());
                config.Optional("JWT_MAX_DURATION", CasConfig.JwtMaxDuration.ToString());
                config.Optional("COMMAND_PASSWORD", await config.CommandPassword(), hideValue: true);

            }

            // add the issuer service
            services.AddSingleton<CasTokenIssuer, CasTokenIssuer>();

            // add the IDPs
            services.AddSingleton<ICasIdp, CasAzureAd>();
            if (!string.IsNullOrEmpty(CasConfig.GoogleClientId))
            {
                services.AddSingleton<ICasIdp, CasGoogleId>();
            }

            // setup CORS policy
            if (CasConfig.AllowedOrigins.Length > 0)
            {
                services.AddCors(options =>
                   {
                       options.AddPolicy("cas-server", builder =>
                       {
                           builder.WithOrigins(CasConfig.AllowedOrigins)
                           .AllowAnyHeader()
                           .AllowAnyMethod()
                           .AllowCredentials();
                       });
                   });
            }

        }

        public static void AddCasServerAuth(this IServiceCollection services)
        {
            AddCasServerAuthAsync(services).Wait();
        }
    }

}