using System;
using dotenv.net;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

namespace dotnetauth
{
    public class Program
    {

        private static string LogLevel
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("LOG_LEVEL");
            }
        }

        private static string HostUrl
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("HOST_URL");
            }
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
                    logging.AddConsole();
                    if (Enum.TryParse(LogLevel, out Microsoft.Extensions.Logging.LogLevel level))
                    {
                        logging.SetMinimumLevel(level);
                    }
                    else
                    {
                        logging.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Information);
                    }
                })
                .UseStartup<Startup>();
            if (!string.IsNullOrEmpty(HostUrl)) builder.UseUrls(HostUrl);
            return builder;
        }


    }
}
