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
using authentication.Controllers;

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
                        ValidIssuer = AuthController.Issuer,
                        ValidAudience = AuthController.Audience,
                        IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(AuthController.SigningKey))
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
                       Uri home = new Uri(AuthController.AppHome);
                       builder.WithOrigins($"{home.Scheme}://{home.Host}", $"{home.Scheme}://{home.Host}:{home.Port}")
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

        public class AutoRenewJwt
        {
            private readonly RequestDelegate Next;
            private readonly Graph Graph;

            public AutoRenewJwt(RequestDelegate next, Graph graph)
            {
                this.Next = next;
                this.Graph = graph;
            }

            public async Task Invoke(HttpContext context)
            {

                // see if the JWT is provided
                var header = context.Request.Headers["Authorization"];
                if (header.Count() > 0)
                {
                    var token = header.First().Replace("Bearer ", "");

                    // see if the JWT is expired
                    var handler = new JwtSecurityTokenHandler();
                    var original = handler.ReadJwtToken(token);
                    if (DateTime.UtcNow >= original.Payload.ValidTo.ToUniversalTime())
                    {

                        // see if the user is still valid
                        var oid = original.Claims.FirstOrDefault(claim => claim.Type == "oid");
                        if (oid != null)
                        {
                            Console.WriteLine("oid = " + oid.Value);
                            bool isEnabled = await Graph.IsUserEnabled(oid.Value);
                            if (isEnabled)
                            {

                                // reissue the token
                                string reissued = AuthController.ReissueToken(original);
                                context.Response.Cookies.Append("user", reissued, new CookieOptions()
                                {
                                    HttpOnly = true,
                                    Secure = true,
                                    Domain = AuthController.BaseDomain,
                                    Path = "/"
                                });

                                // replace the header
                                context.Request.Headers.Remove("Authorization");
                                context.Request.Headers.Append("Authorization", $"Bearer {reissued}");

                            }
                        }
                    }
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
            if (AllowAutoRenew)
            {
                var graph = new Graph();
                graph.Start();
                app.UseMiddleware<AutoRenewJwt>(graph);
            }
            app.UseAuthentication();
            app.UseMvc();
        }
    }
}
