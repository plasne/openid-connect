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

        public IConfiguration Configuration { get; }

        private static bool AllowAutoRenew
        {
            get
            {
                string ar = System.Environment.GetEnvironmentVariable("ALLOW_AUTO_RENEW");
                if (string.IsNullOrEmpty(ar)) return false;
                return (ar.ToUpper() == "TRUE" || ar.ToUpper() == "YES" || ar == "1");
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

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            // add the validator service
            var validator = new TokenValidator();
            services.AddSingleton<TokenValidator>(validator);

            // setup authentication
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        RequireExpirationTime = true,
                        RequireSignedTokens = true,
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = TokenValidator.Issuer,
                        ValidAudience = TokenValidator.Audience,
                        IssuerSigningKey = validator.ValidationKey
                    };
                });

            // setup authorization
            services.AddSingleton<IAuthorizationHandler, XsrfHandler>();
            services.AddAuthorization(options =>
            {
                options.AddPolicy("XSRF", policy =>
                {
                    policy.Requirements.Add(new XsrfRequirement());
                });
                options.DefaultPolicy = options.GetPolicy("XSRF");
            });

            // setup CORS policy
            services.AddCors(options =>
               {
                   options.AddPolicy("apphome",
                   builder =>
                   {
                       builder.WithOrigins(TokenValidator.AllowedOrigins)
                       .AllowAnyHeader()
                       .AllowAnyMethod()
                       .AllowCredentials();
                   });
               });

            // setup MVC
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
                try
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

                }
                catch (Exception e)
                {
                    Console.WriteLine("exception in JwtCookieToHeader...");
                    Console.WriteLine(e.Message);
                    if (e.InnerException != null) Console.WriteLine(e.InnerException.Message);
                }

                // next
                await Next.Invoke(context);

            }
        }

        public class ReissueToken
        {
            private readonly RequestDelegate Next;

            public ReissueToken(RequestDelegate next)
            {
                this.Next = next;
            }

            public async Task Invoke(HttpContext context)
            {
                try
                {

                    // see if the JWT is provided
                    var header = context.Request.Headers["Authorization"];
                    if (header.Count() > 0)
                    {
                        var token = header.First().Replace("Bearer ", "");

                        // see if the token has expired
                        if (TokenValidator.IsTokenExpired(token))
                        {
                            Console.WriteLine("token is expired");
                            string reissued = TokenValidator.ReissueToken(token);

                            // rewrite the header
                            context.Request.Headers.Remove("Authorization");
                            context.Request.Headers.Append("Authorization", $"Bearer {reissued}");
                        }

                    }

                }
                catch (Exception e)
                {
                    Console.WriteLine("exception in ReissueToken...");
                    Console.WriteLine(e.Message);
                    if (e.InnerException != null) Console.WriteLine(e.InnerException.Message);
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
            if (!string.IsNullOrEmpty(TokenValidator.ReissueUrl)) app.UseMiddleware<ReissueToken>();
            app.UseAuthentication();
            app.UseMvc();
        }
    }
}
