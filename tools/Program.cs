using System;
using System.Linq;
using CommandLine;
using dotenv.net;
using CasAuth;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Logging;

namespace tools
{
    class Program
    {

        private static string LogLevel
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("LOG_LEVEL");
            }
        }

        public class IssueOptions
        {

            [Option('o', "oid", Required = false, HelpText = "The GUID of the user.")]
            public string Oid { get; set; }

            [Option('e', "email", Required = false, HelpText = "The email address of the user.")]
            public string Email { get; set; }

            [Option('n', "name", Required = false, HelpText = "The name of the user or service account.")]
            public string Name { get; set; }

            [Option('r', "roles", Required = false, HelpText = "The roles for the user or service account.")]
            public string Roles { get; set; }

            [Option('x', "xsrf", Required = false, HelpText = "The value to assert for XSRF token.")]
            public string Xsrf { get; set; }

        }

        public class ValidateOptions
        {
            [Option('t', "token", Required = true, HelpText = "The token for validation.")]
            public string Token { get; set; }
        }

        public class CertificateOptions
        {
        }

        public class UserOptions
        {
            [Option('o', "oid", Required = false, HelpText = "The oid of the user.")]
            public string Oid { get; set; }
            [Option('e', "email", Required = false, HelpText = "The email of the user.")]
            public string Email { get; set; }
        }

        static void Main(string[] args)
        {

            // ensure a command is specified
            string[] cmds = new string[] { "issue-token", "validate-token", "get-certificates", "get-user", "config-wizard" };
            if (args.Length < 1 || !cmds.Contains(args[0]))
            {
                throw new Exception("you must specify a command from \"issue-token\", \"validate-token\", \"get-certificates\", \"get-user\", or \"config-wizard\".");
            }

            // support dependency injection
            var services = new ServiceCollection();
            services
                .AddLogging(configure => configure.AddConsole())
                .Configure<LoggerFilterOptions>(options =>
                {
                    if (Enum.TryParse(LogLevel, out Microsoft.Extensions.Logging.LogLevel level))
                    {
                        options.MinLevel = level;
                    }
                    else
                    {
                        options.MinLevel = Microsoft.Extensions.Logging.LogLevel.Information;
                    }
                });
            services.AddHttpClient("cas").ConfigurePrimaryHttpMessageHandler(() => new CasProxyHandler());
            services.AddSingleton<CasTokenIssuer>();
            using (var provider = services.BuildServiceProvider())
            {
                using (var scope = provider.CreateScope())
                {

                    // get the configuration
                    DotEnv.Config(throwOnError: false);
                    Action applyConfig = () =>
                    {
                        var logger = scope.ServiceProvider.GetService<ILogger<Program>>();
                        var config = provider.GetService<ICasConfig>();
                        config.Apply().Wait();
                        config.Optional("PROXY", CasEnv.Proxy);
                        config.Optional("USE_INSECURE_DEFAULTS", CasEnv.UseInsecureDefaults, hideValue: false);
                        config.Optional("DEFAULT_HOST_URL", CasEnv.DefaultHostUrl);
                        config.Optional("SERVER_HOST_URL", CasEnv.ServerHostUrl);
                        config.Optional("CLIENT_HOST_URL", CasEnv.ClientHostUrl);
                        config.Optional("WEB_HOST_URL", CasEnv.WebHostUrl);
                        config.Optional("BASE_DOMAIN", CasEnv.BaseDomain());
                        config.Optional("ISSUER", CasEnv.Issuer);
                        config.Optional("AUDIENCE", CasEnv.Audience);
                        config.Optional("WELL_KNOWN_CONFIG_URL", CasEnv.WellKnownConfigUrl);
                        config.Optional("REISSUE_URL", CasEnv.ReissueUrl);
                        config.Optional("ALLOWED_ORIGINS", CasEnv.AllowedOrigins);
                        config.Optional("REQUIRE_SECURE_FOR_COOKIES", CasEnv.RequireSecureForCookies, hideValue: false);
                        config.Optional("REQUIRE_HTTPONLY_ON_USER_COOKIE", CasEnv.RequireHttpOnlyOnUserCookie, hideValue: false);
                        config.Optional("REQUIRE_HTTPONLY_ON_XSRF_COOKIE", CasEnv.RequireHttpOnlyOnXsrfCookie, hideValue: false);
                        config.Optional("VERIFY_TOKEN_IN_HEADER", CasEnv.VerifyTokenInHeader, hideValue: false);
                        config.Optional("VERIFY_TOKEN_IN_COOKIE", CasEnv.VerifyTokenInCookie, hideValue: false);
                        config.Optional("VERIFY_XSRF_IN_HEADER", CasEnv.VerifyXsrfInHeader, hideValue: false);
                        config.Optional("VERIFY_XSRF_IN_COOKIE", CasEnv.VerifyXsrfInCookie, hideValue: false);
                        config.Optional("USER_COOKIE_NAME", CasEnv.UserCookieName);
                        config.Optional("ROLE_FOR_ADMIN", CasEnv.RoleForAdmin);
                        config.Optional("ROLE_FOR_SERVICE", CasEnv.RoleForService);
                        config.Optional("TENANT_ID", CasEnv.TenantId);
                        config.Optional("CLIENT_ID", CasEnv.ClientId);
                        config.Optional("CLIENT_SECRET", CasEnv.ClientSecret);
                        config.Optional("TENANT_ID_CONFIG", CasEnv.TenantIdConfig);
                        config.Optional("CLIENT_ID_CONFIG", CasEnv.ClientIdConfig);
                        config.Optional("CLIENT_SECRET_CONFIG", CasEnv.ClientSecretConfig);
                        config.Optional("TENANT_ID_GRAPH", CasEnv.TenantIdGraph);
                        config.Optional("CLIENT_ID_GRAPH", CasEnv.ClientIdGraph);
                        config.Optional("CLIENT_SECRET_GRAPH", CasEnv.ClientSecretGraph);
                        config.Optional("TENANT_ID_VAULT", CasEnv.TenantIdVault);
                        config.Optional("CLIENT_ID_VAULT", CasEnv.ClientIdVault);
                        config.Optional("CLIENT_SECRET_VAULT", CasEnv.ClientSecretVault);
                        config.Optional("AUTHORITY", CasEnv.Authority);
                        config.Optional("REDIRECT_URI", CasEnv.RedirectUri());
                        config.Optional("DEFAULT_REDIRECT_URL", CasEnv.DefaultRedirectUrl);
                        config.Optional("APPLICATION_ID", CasEnv.ApplicationIds);
                        config.Optional("DOMAIN_HINT", CasEnv.DomainHint);
                        config.Optional("JWT_DURATION", CasEnv.JwtDuration.ToString());
                        config.Optional("JWT_SERVICE_DURATION", CasEnv.JwtServiceDuration.ToString());
                        config.Optional("JWT_MAX_DURATION", CasEnv.JwtMaxDuration.ToString());
                        config.Optional("REQUIRE_USER_ENABLED_ON_REISSUE", CasEnv.RequireUserEnabledOnReissue, hideValue: false);
                        config.Optional("COMMAND_PASSWORD", CasEnv.CommandPassword);
                        config.Optional("PRIVATE_KEY", CasEnv.PrivateKey);
                        config.Optional("PRIVATE_KEY_PASSWORD", CasEnv.PrivateKeyPassword);
                        config.Optional("PUBLIC_CERT_0", CasEnv.PublicCert0);
                        config.Optional("PUBLIC_CERT_1", CasEnv.PublicCert1);
                        config.Optional("PUBLIC_CERT_2", CasEnv.PublicCert2);
                        config.Optional("PUBLIC_CERT_3", CasEnv.PublicCert3);
                    };

                    // execute the proper command
                    switch (args[0])
                    {

                        case "issue-token":
                            {
                                applyConfig();
                                // NOTE: async means main thread won't stay running
                                Parser.Default.ParseArguments<IssueOptions>(args).WithParsed<IssueOptions>(o =>
                                {

                                    // build the claims
                                    // NOTE: claims.Add(key, value) is an extension method which resolves to uri-names and dedupes,
                                    //   we do not want that in the token
                                    var tokenIssuer = scope.ServiceProvider.GetService<CasTokenIssuer>();
                                    var claims = new List<Claim>();
                                    if (!string.IsNullOrEmpty(o.Oid)) claims.Add(new Claim("oid", o.Oid));
                                    if (!string.IsNullOrEmpty(o.Email)) claims.Add(new Claim("email", o.Email));
                                    if (!string.IsNullOrEmpty(o.Name)) claims.Add(new Claim("name", o.Name));
                                    if (!string.IsNullOrEmpty(o.Roles))
                                    {
                                        var roles = o.Roles.Split(',').Select(id => id.Trim());
                                        foreach (var role in roles)
                                        {
                                            claims.Add(new Claim("role", role));
                                        }
                                    }
                                    if (!string.IsNullOrEmpty(o.Xsrf)) claims.Add(new Claim("xsrf", o.Xsrf));

                                    // generate the token
                                    var task = tokenIssuer.IssueToken(claims);
                                    task.Wait();
                                    var jwt_s = task.Result;

                                    // read the compiled token
                                    JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                                    var jwt = handler.ReadJwtToken(jwt_s);

                                    // write the output
                                    Console.WriteLine("");
                                    Console.WriteLine(jwt_s);
                                    Console.WriteLine("");
                                    Console.WriteLine(jwt.Payload.SerializeToJson());
                                    Console.WriteLine("");
                                    Console.WriteLine($"now: {DateTime.UtcNow}");
                                    Console.WriteLine($"from: {jwt.ValidFrom}");
                                    Console.WriteLine($"to: {jwt.ValidTo.ToUniversalTime()}");
                                    var old = jwt.Claims.First(c => c.Type == "old");
                                    if (old != null) Console.WriteLine($"old: {DateTimeOffset.FromUnixTimeSeconds(long.Parse(old.Value)).ToUniversalTime()}");
                                    Console.WriteLine($"len: {jwt_s.Length}");
                                    Console.WriteLine("");

                                });
                                break;
                            }

                        case "validate-token":
                            {
                                applyConfig();
                                Parser.Default.ParseArguments<ValidateOptions>(args).WithParsed<ValidateOptions>(o =>
                                {
                                    var tokenIssuer = scope.ServiceProvider.GetService<CasTokenIssuer>();
                                    var task = tokenIssuer.ValidateToken(o.Token);
                                    task.Wait();
                                    var jwt = task.Result;
                                    Console.WriteLine("");
                                    Console.WriteLine(jwt.Payload.SerializeToJson());
                                    Console.WriteLine("");
                                });
                                break;
                            }

                        case "get-certificates":
                            {
                                applyConfig();
                                Parser.Default.ParseArguments<CertificateOptions>(args).WithParsed<CertificateOptions>(o =>
                                {
                                    var tokenIssuer = scope.ServiceProvider.GetService<CasTokenIssuer>();
                                    var task = tokenIssuer.GetValidationCertificates();
                                    task.Wait();
                                    var certificates = task.Result;
                                    foreach (var certificate in certificates)
                                    {

                                        // get the parameters of the public key
                                        var pubkey = certificate.PublicKey.Key as dynamic;
                                        var parameters = pubkey.ExportParameters(false);

                                        // write out the info
                                        Console.WriteLine("");
                                        Console.WriteLine($"kid: {certificate.Thumbprint}");
                                        string x5t = Convert.ToBase64String(certificate.GetCertHash()).Replace("=", "");
                                        Console.WriteLine($"x5t: {x5t}");
                                        string n = Convert.ToBase64String(parameters.Modulus).Replace("=", "");
                                        Console.WriteLine($"n: {n}");
                                        string e = Convert.ToBase64String(parameters.Exponent);
                                        Console.WriteLine($"e: {e}");
                                        string x5c = Convert.ToBase64String(certificate.RawData);
                                        Console.WriteLine($"x5c: {x5c}");
                                        Console.WriteLine("");

                                    }
                                });
                                break;
                            }

                        case "get-user":
                            {
                                applyConfig();
                                Parser.Default.ParseArguments<UserOptions>(args).WithParsed<UserOptions>(o =>
                                {
                                    var tokenIssuer = scope.ServiceProvider.GetService<CasTokenIssuer>();
                                    if (!string.IsNullOrEmpty(o.Oid))
                                    {
                                        var task = tokenIssuer.GetUserFromGraph(o.Oid);
                                        task.Wait();
                                        Console.WriteLine("");
                                        Console.WriteLine(task.Result);
                                        Console.WriteLine("");
                                    }
                                    else if (!string.IsNullOrEmpty(o.Email))
                                    {
                                        var task = tokenIssuer.GetUserFromGraph("?$filter=mail eq '{email}'");
                                        task.Wait();
                                        Console.WriteLine("");
                                        Console.WriteLine(task.Result);
                                        Console.WriteLine("");
                                    }
                                    else
                                    {
                                        throw new Exception("You must specify either oid or email.");
                                    }
                                });
                                break;
                            }


                    }

                }
            }

        }




    }
}
