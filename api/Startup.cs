using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Linq;
using dotenv.net;

namespace dotnetauth
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
            DotEnv.Config(false);
        }

        private string Issuer
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("ISSUER");
            }
        }

        private string Audience
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("AUDIENCE");
            }
        }

        private string SigningKey
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("SIGNING_KEY");
            }
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            // setup JWT Bearer Auth
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = this.Issuer,
                        ValidAudience = this.Audience,
                        IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(this.SigningKey))
                    };
                });

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
        }

        public class JwtCookieToHeader
        {
            private readonly RequestDelegate _next;

            public JwtCookieToHeader(RequestDelegate next)
            {
                _next = next;
            }

            public async Task Invoke(HttpContext context)
            {
                string cookie = context.Request.Cookies["user"];
                if (!string.IsNullOrEmpty(cookie))
                {
                    context.Request.Headers.Append("Authorization", "Bearer " + cookie);
                }
                await _next.Invoke(context);
            }
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseMiddleware<JwtCookieToHeader>();
            app.UseAuthentication();
            app.UseMvc();
        }
    }
}
