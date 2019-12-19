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

            var bytes = System.IO.File.ReadAllBytes("/Users/plasne/Documents/keys/cert.pfx");
            var certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(bytes, "Vampyr0000!!!!");
            var signingCredentials = new Microsoft.IdentityModel.Tokens.X509SigningCredentials(certificate, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha256);
            var claims = new System.Collections.Generic.List<System.Security.Claims.Claim>();
            claims.Add(new System.Security.Claims.Claim("sub", "663c73c9-47e1-4a11-9a74-620d7e291c45"));
            claims.Add(new System.Security.Claims.Claim("jti", System.Guid.NewGuid().ToString()));
            var jwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
                issuer: "663c73c9-47e1-4a11-9a74-620d7e291c45",
                audience: "https://login.microsoftonline.com/a5f2ede2-d815-4bca-a46d-b007a3e1571a/oauth2/token",
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddMinutes(60),
                signingCredentials: signingCredentials);
            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            Console.WriteLine("=================");
            var encoded = handler.WriteToken(jwt);
            Console.WriteLine(encoded);
            Console.WriteLine("=================");


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
