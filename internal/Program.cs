using dotenv.net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using CasAuth;
using Microsoft.AspNetCore;
using NetBricks;

namespace internal_svc
{
    public class Program
    {

        private static string HostUrl
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("HOST_URL");
            }
        }

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
