using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace dotnetauth
{
    public class Startup
    {

        public Startup(IConfiguration configuration, ILogger<Startup> logger, ILoggerFactory factory)
        {

            // set the logger so it can be used in services
            this.LoggerFactory = factory;

            // determine the authentication type
            string authType = AuthChooser.AuthType();
            if (authType == "app") logger.LogInformation("authentication: application ClientId and ClientSecret (service principal).");
            if (authType == "mi") logger.LogInformation("authentication: managed identity with failback to az cli.");

            // load the configuration
            logger.LogInformation("Loading configuration...");
            Config.Apply().Wait();

            // confirm and log the configuration
            logger.LogDebug(Config.Require("AUTHORITY"));
            logger.LogDebug(Config.Require("REDIRECT_URI"));
            logger.LogDebug(Config.Require("ISSUER"));
            logger.LogDebug(Config.Require("AUDIENCE"));
            logger.LogDebug(Config.Require("DEFAULT_REDIRECT_URL"));
            logger.LogDebug(Config.Require("ALLOWED_ORIGINS"));
            logger.LogDebug(Config.Require("BASE_DOMAIN"));
            logger.LogDebug(Config.Require("CLIENT_ID"));
            logger.LogDebug(Config.Require("PUBLIC_KEYS_URL"));
            logger.LogDebug(Config.Require("PRIVATE_KEY", "KEYVAULT_PRIVATE_KEY_URL"));
            logger.LogDebug(Config.Require("PRIVATE_KEY_PASSWORD", "KEYVAULT_PRIVATE_KEY_PASSWORD_URL"));
            logger.LogDebug(Config.Require("PUBLIC_CERT_0", "PUBLIC_CERT_1", "PUBLIC_CERT_2", "PUBLIC_CERT_3", "KEYVAULT_PUBLIC_CERT_PREFIX_URL"));
            logger.LogDebug(Config.Optional("ID_TOKEN_ISSUER"));
            logger.LogDebug(Config.Optional("AUTH_TYPE")); // set to "app" to use an app service principal
            if (authType == "app")
            {
                logger.LogDebug(Config.Require("TENANT_ID"));
                logger.LogDebug(Config.Require("CLIENT_SECRET"));
            }
            else
            {
                logger.LogDebug(Config.Optional("KEYVAULT_CLIENT_SECRET_URL")); // use for AuthCode flow with AUTH_TYPE=mi
            }
            logger.LogDebug(Config.Optional("AUTH_TYPE_CONFIG"));
            logger.LogDebug(Config.Optional("AUTH_TYPE_VAULT"));
            logger.LogDebug(Config.Optional("AUTH_TYPE_GRAPH"));
            logger.LogDebug(Config.Optional("APPCONFIG_RESOURCE_ID")); // use to get settings from Azure App Config
            logger.LogDebug(Config.Optional("CONFIG_KEYS")); // specify the keys to get from Azure App Config
            logger.LogDebug(Config.Optional("APPLICATION_ID")); // use to assert roles
            logger.LogDebug(Config.Optional("REQUIRE_SECURE_FOR_COOKIES")); // set to "false" if you don't want cookies marked "secure"
            logger.LogDebug(Config.Optional("REQUIRE_USER_ENABLED_ON_REISSUE")); // set to "false" if you don't want to check for the user being enabled
            logger.LogDebug(Config.Optional("COMMAND_PASSWORD", "KEYVAULT_COMMAND_PASSWORD_URL")); // set a password required to send commands like clear-cache
            logger.LogDebug(Config.Optional("REQUIRE_HTTPONLY_ON_USER_COOKIE"));
            logger.LogDebug(Config.Optional("REQUIRE_HTTPONLY_ON_XSRF_COOKIE"));
            logger.LogDebug(Config.Optional("VERIFY_XSRF_IN_HEADER"));
            logger.LogDebug(Config.Optional("VERIFY_XSRF_IN_COOKIE"));

        }

        private ILoggerFactory LoggerFactory { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            // add the issuer service
            services.AddSingleton<TokenIssuer>(new TokenIssuer(LoggerFactory));

            // setup CORS policy
            services.AddCors(options =>
               {
                   options.AddPolicy("origins",
                   builder =>
                   {
                       builder.WithOrigins(TokenIssuer.AllowedOrigins)
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
