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
            if (AuthChooser.AuthType == "app") logger.LogInformation("authentication: application ClientId and ClientSecret (service principal).");
            if (AuthChooser.AuthType == "mi") logger.LogInformation("authentication: managed identity with failback to az cli.");

            // load the configuration
            logger.LogInformation("Loading configuration...");
            Config.Apply(null, factory).Wait();
            Config.Require(new string[] {
                "AUTHORITY",
                "REDIRECT_URI",
                "ISSUER",
                "AUDIENCE",
                "DEFAULT_REDIRECT_URL",
                "ALLOWED_ORIGINS",
                "BASE_DOMAIN",
                "CLIENT_ID",
                "KEYVAULT_PRIVATE_KEY_URL",
                "KEYVAULT_PRIVATE_KEY_PASSWORD_URL",
                "KEYVAULT_PUBLIC_CERT_URL"
            });
            Config.Optional(new string[] {

                "AUTH_TYPE",                 // set to "app" to use an app service principal
                "APPCONFIG_RESOURCE_ID",     // use to get settings from Azure App Config
                "CONFIG_KEYS",               // specify the keys to get from Azure App Config
                "TENANT_ID",                 // required if using AUTH_TYPE=app
                "CLIENT_ID",                 // required if using AUTH_TYPE=app
                "CLIENT_SECRET",             // required if using AUTH_TYPE=app
                "APPLICATION_ID",            // use to assert roles
                "KEYVAULT_CLIENT_SECRET_URL" // use for AuthCode flow with AUTH_TYPE=mi
            });
            logger.LogInformation("Configuration loaded.");

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
