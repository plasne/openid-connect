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

            // load the configuration
            logger.LogInformation("Loading configuration...");
            Config.Load(factory).Wait();
            Config.Require(new string[] {
                "AUTHORITY",
                "REDIRECT_URI",
                "ISSUER",
                "AUDIENCE",
                "DEFAULT_REDIRECT_URL",
                "ALLOWED_ORIGINS",
                "BASE_DOMAIN",
                "APPLICATION_ID",  // enable this to get role assignments
                "CLIENT_ID",
                // "KEYVAULT_CLIENT_SECRET_URL",  // enable this if obtaining an authorization code for the user
                "KEYVAULT_PRIVATE_KEY_URL",
                "KEYVAULT_PRIVATE_KEY_PASSWORD_URL",
                "KEYVAULT_PUBLIC_CERT_URL"
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
