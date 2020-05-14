using System;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using dotenv.net;

namespace auth
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

        private static int Port
        {
            get
            {
                string sport = System.Environment.GetEnvironmentVariable("PORT");
                if (int.TryParse(sport, out int port))
                {
                    return port;
                }
                else
                {
                    return 5100;
                }
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
                    if (Enum.TryParse(LogLevel, true, out Microsoft.Extensions.Logging.LogLevel level))
                    {
                        logging.SetMinimumLevel(level);
                    }
                    else
                    {
                        logging.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Information);
                    }
                })
                .UseStartup<Startup>();
            builder.UseUrls($"http://*:{Port}");
            return builder;
        }

    }
}
