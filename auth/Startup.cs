﻿using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using CasAuth;
using ext = CasAuth.UseCasServerAuthMiddlewareExtensions;
using System.Net.Http;

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
            services.AddCasServerAuth();

        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();
            app.UseCors();
            app.UseCasServerAuth(() =>
            {
                var opt = new ext.CasServerAuthOptions()
                {
                    AuthCodeFunc = async (getAcessToken) =>
                    {
                        var token1 = await getAcessToken("offline_access https://graph.microsoft.com/user.read");
                        // var token2 = await getAcessToken("offline_access https://graph.microsoft.com/group.read");
                    },
                    ClaimBuilderFunc = (inClaims, outClaims) =>
                    {
                        outClaims.Add(new System.Security.Claims.Claim("color", "yellow"));
                    }
                };
                opt.Scopes.Add("https://graph.microsoft.com/user.read");
                // opt.Scopes.Add("https://graph.microsoft.com/group.read");
                return opt;
            });
        }

    }
}
