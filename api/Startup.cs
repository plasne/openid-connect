using System;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
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

        private string AppHome
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("APP_HOME");
            }
        }

        public class CustomJwtSecurityTokenHandler : ISecurityTokenValidator
        {

            private int maxTokenSizeInBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
            private JwtSecurityTokenHandler tokenHandler;
            private HttpContext httpContext;

            public CustomJwtSecurityTokenHandler(IHttpContextAccessor httpContextAccessor)
            {
                this.tokenHandler = new JwtSecurityTokenHandler();
                this.httpContext = httpContextAccessor.HttpContext;
            }

            public bool CanValidateToken
            {
                get
                {
                    return tokenHandler.CanValidateToken;
                }
            }

            public int MaximumTokenSizeInBytes
            {
                get
                {
                    return this.maxTokenSizeInBytes;
                }
                set
                {
                    this.maxTokenSizeInBytes = value;
                }
            }

            public bool CanReadToken(string securityToken)
            {
                return tokenHandler.CanReadToken(securityToken);
            }

            public ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
            {
                var principal = tokenHandler.ValidateToken(securityToken, validationParameters, out validatedToken);

                // ensure the XSRF matches
                string xsrfFromCookie = this.httpContext.Request.Cookies["xsrf"];
                var xsrfFromJwt = principal.Claims.First(claim => claim.Type == "xsrf");
                if (xsrfFromJwt == null || xsrfFromJwt.Value != xsrfFromCookie)
                {
                    throw new SecurityTokenValidationException("XSRF does not match");
                }

                return principal;
            }

        }

        private class XsrfRequirement : IAuthorizationRequirement
        {
        }

        private class XsrfHandler : AuthorizationHandler<XsrfRequirement>
        {
            protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, XsrfRequirement requirement)
            {
                if (context.Resource is AuthorizationFilterContext mvc)
                {
                    try
                    {
                        var identity = context.User.Identity as ClaimsIdentity;
                        if (identity == null) throw new Exception("identity not found");
                        string token = mvc.HttpContext.Request.Headers["X-XSRF-TOKEN"];
                        if (string.IsNullOrEmpty(token)) throw new Exception("X-XSRF-TOKEN not sent");
                        var claim = identity.FindFirst(c => c.Type == "xsrf");
                        if (claim == null) throw new Exception("xsrf claim not found");
                        if (token != claim.Value) throw new Exception("xsrf claim does not match X-XSRF-TOKEN");
                        context.Succeed(requirement);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("authorization failure - " + e.Message);
                        context.Fail();
                    }
                }
                else
                {
                    Console.WriteLine("authorization failure - context.Resource is not AuthorizationFilterContext");
                    context.Fail();
                }
                return Task.CompletedTask;
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

            services.AddSingleton<IAuthorizationHandler, XsrfHandler>();
            services.AddAuthorization(options =>
            {
                options.AddPolicy("XSRF", policy =>
                {
                    policy.Requirements.Add(new XsrfRequirement());
                });
                options.DefaultPolicy = options.GetPolicy("XSRF");
            });

            services.AddCors(options =>
               {
                   options.AddPolicy("apphome",
                   builder =>
                   {
                       Uri home = new Uri(this.AppHome);
                       builder.WithOrigins($"{home.Scheme}://{home.Host}")
                       .AllowAnyHeader()
                       .AllowAnyMethod()
                       .AllowCredentials();
                   });
               });

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
        }

        public class JwtCookieToHeader
        {
            private readonly RequestDelegate Next;

            public JwtCookieToHeader(RequestDelegate next)
            {
                this.Next = next;
            }

            public async Task Invoke(HttpContext context)
            {

                // remove any existing authorization header
                //  note: this ensures someone cannot send something with a madeup xsrf claim
                context.Request.Headers.Remove("Authorization");

                // add the authorization header from the user HttpOnly cookie
                string cookie = context.Request.Cookies["user"];
                if (!string.IsNullOrEmpty(cookie))
                {
                    context.Request.Headers.Append("Authorization", "Bearer " + cookie);
                }

                // next
                await Next.Invoke(context);

            }
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseCors("apphome");
            app.UseMiddleware<JwtCookieToHeader>();
            app.UseAuthentication();
            app.UseMvc();
        }
    }
}
