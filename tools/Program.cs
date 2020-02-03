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

            [Option('n', "name", Required = true, HelpText = "The name of the user or service account.")]
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
                .AddLogging(configure => configure.AddConsole(c =>
                {
                    c.Format = Microsoft.Extensions.Logging.Console.ConsoleLoggerFormat.Systemd;
                }))
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
                        var httpClientFactory = scope.ServiceProvider.GetService<IHttpClientFactory>();
                        var httpClient = httpClientFactory.CreateClient("cas");
                        CasConfig.Apply(httpClient).Wait();
                        var logger = scope.ServiceProvider.GetService<ILogger<Program>>();
                        CasConfig.Optional("PROXY", CasEnv.Proxy, logger);
                        CasConfig.Optional("USE_INSECURE_DEFAULTS", CasEnv.UseInsecureDefaults, logger);
                        CasConfig.Optional("DEFAULT_HOST_URL", CasEnv.DefaultHostUrl, logger);
                        CasConfig.Optional("SERVER_HOST_URL", CasEnv.ServerHostUrl, logger);
                        CasConfig.Optional("CLIENT_HOST_URL", CasEnv.ClientHostUrl, logger);
                        CasConfig.Optional("WEB_HOST_URL", CasEnv.WebHostUrl, logger);
                        CasConfig.Optional("BASE_DOMAIN", CasEnv.BaseDomain, logger);
                        CasConfig.Optional("ISSUER", CasEnv.Issuer, logger);
                        CasConfig.Optional("AUDIENCE", CasEnv.Audience, logger);
                        CasConfig.Optional("WELL_KNOWN_CONFIG_URL", CasEnv.WellKnownConfigUrl, logger);
                        CasConfig.Optional("REISSUE_URL", CasEnv.ReissueUrl, logger);
                        CasConfig.Optional("ALLOWED_ORIGINS", CasEnv.AllowedOrigins, logger);
                        CasConfig.Optional("REQUIRE_SECURE_FOR_COOKIES", CasEnv.RequireSecureForCookies, logger);
                        CasConfig.Optional("REQUIRE_HTTPONLY_ON_USER_COOKIE", CasEnv.RequireHttpOnlyOnUserCookie, logger);
                        CasConfig.Optional("REQUIRE_HTTPONLY_ON_XSRF_COOKIE", CasEnv.RequireHttpOnlyOnXsrfCookie, logger);
                        CasConfig.Optional("VERIFY_TOKEN_IN_HEADER", CasEnv.VerifyTokenInHeader, logger);
                        CasConfig.Optional("VERIFY_TOKEN_IN_COOKIE", CasEnv.VerifyTokenInCookie, logger);
                        CasConfig.Optional("VERIFY_XSRF_IN_HEADER", CasEnv.VerifyXsrfInHeader, logger);
                        CasConfig.Optional("VERIFY_XSRF_IN_COOKIE", CasEnv.VerifyXsrfInCookie, logger);
                        CasConfig.Optional("USER_COOKIE_NAME", CasEnv.UserCookieName, logger);
                        CasConfig.Optional("ROLE_FOR_ADMIN", CasEnv.RoleForAdmin, logger);
                        CasConfig.Optional("ROLE_FOR_SERVICE", CasEnv.RoleForService, logger);
                        CasConfig.Optional("TENANT_ID", CasEnv.TenantId, logger);
                        CasConfig.Optional("CLIENT_ID", CasEnv.ClientId, logger);
                        CasConfig.Optional("CLIENT_SECRET", CasEnv.ClientSecret, logger);
                        CasConfig.Optional("TENANT_ID_CONFIG", CasEnv.TenantIdConfig, logger);
                        CasConfig.Optional("CLIENT_ID_CONFIG", CasEnv.ClientIdConfig, logger);
                        CasConfig.Optional("CLIENT_SECRET_CONFIG", CasEnv.ClientSecretConfig, logger);
                        CasConfig.Optional("TENANT_ID_GRAPH", CasEnv.TenantIdGraph, logger);
                        CasConfig.Optional("CLIENT_ID_GRAPH", CasEnv.ClientIdGraph, logger);
                        CasConfig.Optional("CLIENT_SECRET_GRAPH", CasEnv.ClientSecretGraph, logger);
                        CasConfig.Optional("TENANT_ID_VAULT", CasEnv.TenantIdVault, logger);
                        CasConfig.Optional("CLIENT_ID_VAULT", CasEnv.ClientIdVault, logger);
                        CasConfig.Optional("CLIENT_SECRET_VAULT", CasEnv.ClientSecretVault, logger);
                        CasConfig.Optional("AUTHORITY", CasEnv.Authority, logger);
                        CasConfig.Optional("REDIRECT_URI", CasEnv.RedirectUri, logger);
                        CasConfig.Optional("DEFAULT_REDIRECT_URL", CasEnv.DefaultRedirectUrl, logger);
                        CasConfig.Optional("APPLICATION_ID", CasEnv.ApplicationIds, logger);
                        CasConfig.Optional("DOMAIN_HINT", CasEnv.DomainHint, logger);
                        CasConfig.Optional("KEYVAULT_CLIENT_SECRET_URL", CasEnv.KeyvaultClientSecretUrl, logger);
                        CasConfig.Optional("KEYVAULT_CLIENT_SECRET_GRAPH_URL", CasEnv.KeyvaultClientSecretGraphUrl, logger);
                        CasConfig.Optional("JWT_DURATION", CasEnv.JwtDuration.ToString(), logger);
                        CasConfig.Optional("JWT_SERVICE_DURATION", CasEnv.JwtServiceDuration.ToString(), logger);
                        CasConfig.Optional("JWT_MAX_DURATION", CasEnv.JwtMaxDuration.ToString(), logger);
                        CasConfig.Optional("REQUIRE_USER_ENABLED_ON_REISSUE", CasEnv.RequireUserEnabledOnReissue, logger);
                        CasConfig.Optional("COMMAND_PASSWORD", CasEnv.CommandPassword, logger);
                        CasConfig.Optional("KEYVAULT_COMMAND_PASSWORD_URL", CasEnv.KeyvaultCommandPasswordUrl, logger);
                        CasConfig.Optional("PRIVATE_KEY", CasEnv.PrivateKey, logger);
                        CasConfig.Optional("KEYVAULT_PRIVATE_KEY_URL", CasEnv.KeyvaultPrivateKeyUrl, logger);
                        CasConfig.Optional("PRIVATE_KEY_PASSWORD", CasEnv.PrivateKeyPassword, logger);
                        CasConfig.Optional("KEYVAULT_PRIVATE_KEY_PASSWORD_URL", CasEnv.KeyvaultPrivateKeyPasswordUrl, logger);
                        CasConfig.Optional("PUBLIC_CERT_0", System.Environment.GetEnvironmentVariable("PUBLIC_CERT_0"), logger);
                        CasConfig.Optional("PUBLIC_CERT_1", System.Environment.GetEnvironmentVariable("PUBLIC_CERT_1"), logger);
                        CasConfig.Optional("PUBLIC_CERT_2", System.Environment.GetEnvironmentVariable("PUBLIC_CERT_2"), logger);
                        CasConfig.Optional("PUBLIC_CERT_3", System.Environment.GetEnvironmentVariable("PUBLIC_CERT_3"), logger);
                        CasConfig.Optional("KEYVAULT_PUBLIC_CERT_PREFIX_URL", CasEnv.KeyvaultPublicCertPrefixUrl, logger);
                    };

                    // execute the proper command
                    switch (args[0])
                    {

                        case "issue-token":
                            {
                                applyConfig();
                                Parser.Default.ParseArguments<IssueOptions>(args).WithParsed<IssueOptions>(async o =>
                                {

                                    // build the claims
                                    // NOTE: claims.Add(key, value) is an extension method which resolves to uri-names and dedupes,
                                    //   we do not want that in the token
                                    var tokenIssuer = scope.ServiceProvider.GetService<CasTokenIssuer>();
                                    var claims = new List<Claim>();
                                    if (!string.IsNullOrEmpty(o.Oid)) claims.Add(new Claim("oid", o.Oid));
                                    if (!string.IsNullOrEmpty(o.Email)) claims.Add(new Claim("email", o.Email));
                                    claims.Add(new Claim("name", o.Name));
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
                                    var jwt_s = await tokenIssuer.IssueToken(claims);

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
                                Parser.Default.ParseArguments<ValidateOptions>(args).WithParsed<ValidateOptions>(async o =>
                                {
                                    var tokenIssuer = scope.ServiceProvider.GetService<CasTokenIssuer>();
                                    var jwt = await tokenIssuer.ValidateToken(o.Token);
                                    Console.WriteLine("");
                                    Console.WriteLine(jwt.Payload.SerializeToJson());
                                    Console.WriteLine("");
                                });
                                break;
                            }

                        case "get-certificates":
                            {
                                applyConfig();
                                Parser.Default.ParseArguments<CertificateOptions>(args).WithParsed<CertificateOptions>(async o =>
                                {
                                    var tokenIssuer = scope.ServiceProvider.GetService<CasTokenIssuer>();
                                    var certificates = await tokenIssuer.GetValidationCertificates();
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
                                Parser.Default.ParseArguments<UserOptions>(args).WithParsed<UserOptions>(async o =>
                                {
                                    var tokenIssuer = scope.ServiceProvider.GetService<CasTokenIssuer>();
                                    if (!string.IsNullOrEmpty(o.Oid))
                                    {
                                        var user = await tokenIssuer.GetUserFromGraph(o.Oid);
                                        Console.WriteLine("");
                                        Console.WriteLine(user);
                                        Console.WriteLine("");
                                    }
                                    else if (!string.IsNullOrEmpty(o.Email))
                                    {
                                        var user = await tokenIssuer.GetUserFromGraph("?$filter=mail eq '{email}'");
                                        Console.WriteLine("");
                                        Console.WriteLine(user);
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
