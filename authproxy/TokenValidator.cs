using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace authproxy
{

    public class TokenValidator
    {

        public TokenValidator()
        {
            this.ConfigManager = new ConfigurationManager<OpenIdConnectConfiguration>(Program.WellKnownConfigUrl, new OpenIdConnectConfigurationRetriever());
        }

        private ConfigurationManager<OpenIdConnectConfiguration> ConfigManager { get; }

        public async Task<JwtSecurityToken> ValidateToken(string token)
        {

            // get the validation-certificates
            var config = await ConfigManager.GetConfigurationAsync();

            // parameters to validate
            var handler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidateIssuer = (Program.Issuer.Length > 0),
                ValidIssuers = Program.Issuer,
                ValidateAudience = (Program.Audience.Length > 0),
                ValidAudiences = Program.Audience,
                ValidateLifetime = true,
                IssuerSigningKeys = config.SigningKeys
            };

            // validate all previously defined parameters
            SecurityToken validatedSecurityToken = null;
            handler.ValidateToken(token, validationParameters, out validatedSecurityToken);
            JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;

            return validatedJwt;
        }

    }

}