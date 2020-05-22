﻿using dotenv.net;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using CasAuth;
using NetBricks;

namespace dotnetauth
{
    public class Program
    {

        private static int Port
        {
            get => CasConfig.GetOnce("PORT").AsInt(() => 5200);
        }

        public static void Main(string[] args)
        {
            DotEnv.Config(throwOnError: false);
            CreateWebHostBuilder(args).Build().Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args)
        {
            var builder = WebHost.CreateDefaultBuilder(args)
                .ConfigureLogging(logging =>
                {
                    logging.ClearProviders();
                })
                .UseStartup<Startup>();
            builder.UseUrls($"http://*:{Port}");
            return builder;
        }


    }
}
