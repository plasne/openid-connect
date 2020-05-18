using System.Linq;
using dotenv.net;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

namespace authproxy
{
    class Program
    {

        // NOTE: SingleLineConsoleLogger also includes:
        //  LOG_LEVEL (string)
        //  DISABLE_COLORS (bool)

        public static int FromPort
        {
            get
            {
                string sport = System.Environment.GetEnvironmentVariable("FROM_PORT");
                if (int.TryParse(sport, out int port))
                {
                    return port;
                }
                else
                {
                    return 8080;
                }
            }
        }

        public static int ToPort
        {
            get
            {
                string sport = System.Environment.GetEnvironmentVariable("TO_PORT");
                if (int.TryParse(sport, out int port))
                {
                    return port;
                }
                else
                {
                    return 8081;
                }
            }
        }

        public static string ToHost
        {
            get => System.Environment.GetEnvironmentVariable("TO_HOST") ?? "localhost";
        }

        public static bool AllowAnonymous
        {
            get
            {
                string val = System.Environment.GetEnvironmentVariable("ALLOW_ANONYMOUS");
                if (new string[] { "true", "1", "yes" }.Contains(val?.ToLower())) return true;
                return false;
            }
        }

        public static string JwtHeader
        {
            get => System.Environment.GetEnvironmentVariable("JWT_HEADER");
        }

        public static string JwtCookie
        {
            get => System.Environment.GetEnvironmentVariable("JWT_COOKIE");
        }

        public static string XsrfHeader
        {
            get => System.Environment.GetEnvironmentVariable("XSRF_HEADER");
        }

        public static string XsrfClaim
        {
            get => System.Environment.GetEnvironmentVariable("XSRF_CLAIM");
        }

        public static string WellKnownConfigUrl
        {
            get => System.Environment.GetEnvironmentVariable("WELL_KNOWN_CONFIG_URL");
        }

        public static string[] Issuer
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("ISSUER");
                if (string.IsNullOrEmpty(s)) return new string[] { };
                return s.Split(',').Select(id => id.Trim()).ToArray();
            }
        }

        public static string[] Audience
        {
            get
            {
                string s = System.Environment.GetEnvironmentVariable("AUDIENCE");
                if (string.IsNullOrEmpty(s)) return new string[] { };
                return s.Split(',').Select(id => id.Trim()).ToArray();
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
                    logging.ClearProviders();
                })
                .UseStartup<Startup>();
            builder.UseUrls($"http://*:{FromPort}");
            return builder;
        }

    }
}
