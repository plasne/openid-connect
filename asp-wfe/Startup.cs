using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using CasAuth;
using NetBricks;

namespace asp_wfe
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddHttpClient("wfe");
            services.AddCasClientAuth();
            services.AddControllersWithViews();
            //services.AddHttpClient<HomeController>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {

            // log settings
            var config = app.ApplicationServices.GetService<IConfig>();
            config.Optional("LOGIN_URL");
            config.Optional("REDIRECT_URL");
            config.Optional("ME_URL");

            if (env.IsDevelopment()) app.UseDeveloperExceptionPage();

            // route and authenticate
            app.UseRouting();
            app.UseStaticFiles();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseCasClientAuth();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });

        }
    }
}
