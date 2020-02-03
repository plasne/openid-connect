using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using CasAuth;

namespace dotnetauth
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        private IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {

            // setup CasAuth
            services.AddCasClientAuth();

            // add an HttpClient for the api that supports propogating headers and the proxy settings
            //    NOTE: if you are not using AKS and microservices in an overlay network, you probably
            //    do not want to implement these below lines
            services.AddSingleton<CasIntPropogateHeadersOptions>(p =>
            {
                var options = new CasIntPropogateHeadersOptions();
                options.Headers.Add("x-custom-header");
                return options;
            });
            services.AddTransient<CasIntPropogateHeaders>();
            services.AddHttpClient("api")
                .AddHttpMessageHandler<CasIntPropogateHeaders>()
                .ConfigurePrimaryHttpMessageHandler(() => new CasProxyHandler());

            // setup controllers
            services.AddControllers();

        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            app.UseCors();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseCasClientAuth();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }

    }
}
