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
            [Option('r', "role", Required = true, HelpText = "The role for the user.")]
            public string Role { get; set; }
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
            [Option('e', "email", Required = true, HelpText = "The email of the user.")]
            public string Email { get; set; }
        }

        static void Main(string[] args)
        {

            // ensure a command is specified
            string[] cmds = new string[] { "issue", "validate", "user" };
            if (args.Length < 1 || !cmds.Contains(args[0]))
            {
                throw new Exception("you must specify a command from \"issue\", \"validate\", or \"user\".");
            }

            // get the configuration
            DotEnv.Config(throwOnError: false);
            Config.Load().Wait();
            Config.Require(new string[] {
                "ISSUER",
                "AUDIENCE",
                "KEYVAULT_PRIVATE_KEY_URL",
                "KEYVAULT_PRIVATE_KEY_PASSWORD_URL",
                "KEYVAULT_PUBLIC_CERT_URL"
            });

            // create the cmd object
            var cmd = new Cmd();

            // execute the proper command
            switch (args[0])
            {

                case "issue":
                    Parser.Default.ParseArguments<IssueOptions>(args)
                        .WithParsed<IssueOptions>(o =>
                        {
                            if (o.Duration > 0) cmd.JwtDuration = o.Duration;
                            if (o.Max > 0) cmd.JwtMaxDuration = o.Max;
                            if (string.IsNullOrEmpty(o.Xsrf)) cmd.Xsrf = o.Xsrf;
                            cmd.IssueToken(o.Oid, o.DisplayName, o.Email, new string[] { o.Role }).Wait();
                        });
                    break;

                case "validate":
                    Parser.Default.ParseArguments<ValidateOptions>(args)
                        .WithParsed<ValidateOptions>(o =>
                        {
                            cmd.ValidateToken(o.Token).Wait();
                        });
                    break;

                case "user":
                    Parser.Default.ParseArguments<UserOptions>(args)
                        .WithParsed<UserOptions>(o =>
                        {
                            cmd.GetUserFromGraph(o.Email).Wait();
                        });
                    break;

            }

        }
    }
}
