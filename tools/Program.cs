using System;
using System.Linq;
using CommandLine;
using dotenv.net;

namespace tools
{
    class Program
    {

        public class IssueOptions
        {
            [Option('o', "oid", Required = true, HelpText = "The GUID of the user.")]
            public string Oid { get; set; }
            [Option('e', "email", Required = true, HelpText = "The email address of the user.")]
            public string Email { get; set; }
            [Option('n', "display-name", Required = true, HelpText = "The display name of the user.")]
            public string DisplayName { get; set; }
            [Option('r', "roles", Required = true, HelpText = "The roles for the user.")]
            public string Roles { get; set; }
            [Option('x', "xsrf", Required = false, HelpText = "The value to assert for XSRF token.")]
            public string Xsrf { get; set; }
            [Option('d', "duration", Required = false, HelpText = "The duration in minutes to issue the token.")]
            public int Duration { get; set; }
            [Option('m', "max", Required = false, HelpText = "The maxiumum duration in minutes to issue the token.")]
            public int Max { get; set; }
        }

        public class ValidateOptions
        {
            [Option('t', "token", Required = true, HelpText = "The token for validation.")]
            public string Token { get; set; }
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
            string[] cmds = new string[] { "issue-token", "validate-token", "get-certificates", "get-user", "get-config", "config-wizard" };
            if (args.Length < 1 || !cmds.Contains(args[0]))
            {
                throw new Exception("you must specify a command from \"issue-token\", \"validate-token\", \"get-certificates\", \"get-user\", \"get-config\", or \"config-wizard\".");
            }

            // get the configuration
            DotEnv.Config(throwOnError: false);
            Action applyConfig = () =>
            {
                Config.Apply().Wait();
                Console.WriteLine(Config.Require("ISSUER"));
                Console.WriteLine(Config.Require("AUDIENCE"));
                Console.WriteLine(Config.Require("KEYVAULT_PRIVATE_KEY_URL", "KEYVAULT_PRIVATE_KEY_URL"));
                Console.WriteLine(Config.Require("KEYVAULT_PRIVATE_KEY_PASSWORD_URL", "KEYVAULT_PRIVATE_KEY_PASSWORD_URL"));
                Console.WriteLine(Config.Require("PUBLIC_CERT_0", "PUBLIC_CERT_1", "PUBLIC_CERT_2", "PUBLIC_CERT_3", "KEYVAULT_PUBLIC_CERT_PREFIX_URL"));
            };

            // create the cmd object
            var cmd = new Cmd();

            // execute the proper command
            switch (args[0])
            {

                case "issue-token":
                    applyConfig();
                    Parser.Default.ParseArguments<IssueOptions>(args)
                        .WithParsed<IssueOptions>(o =>
                        {
                            if (o.Duration > 0) cmd.JwtDuration = o.Duration;
                            if (o.Max > 0) cmd.JwtMaxDuration = o.Max;
                            if (!string.IsNullOrEmpty(o.Xsrf)) cmd.Xsrf = o.Xsrf;
                            var roles = o.Roles.Split(',').Select(id => id.Trim());
                            cmd.IssueToken(o.Oid, o.DisplayName, o.Email, roles);
                        });
                    break;

                case "validate-token":
                    applyConfig();
                    Parser.Default.ParseArguments<ValidateOptions>(args)
                        .WithParsed<ValidateOptions>(o =>
                        {
                            cmd.ValidateToken(o.Token);
                        });
                    break;

                case "get-certificates":
                    applyConfig();
                    cmd.GetCertificates();
                    break;

                case "get-user":
                    applyConfig();
                    Parser.Default.ParseArguments<UserOptions>(args)
                        .WithParsed<UserOptions>(o =>
                        {
                            if (!string.IsNullOrEmpty(o.Oid))
                            {
                                cmd.GetUserFromGraphByOid(o.Oid).Wait();
                            }
                            else if (!string.IsNullOrEmpty(o.Email))
                            {
                                cmd.GetUserFromGraphByEmail(o.Email).Wait();
                            }
                            else
                            {
                                throw new Exception("You must specify either oid or email.");
                            }
                        });
                    break;

                case "get-config":
                    cmd.GetAllConfig().Wait();
                    break;

                case "config-wizard":
                    cmd.RunConfigWizard();
                    break;

            }

        }
    }
}
