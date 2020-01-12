using System;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Collections.Specialized;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Threading.Tasks;

namespace CasAuth
{

    public class CasTokenValidator
    {

        public CasTokenValidator(ILogger<CasTokenValidator> logger)
        {
            this.Logger = logger;
            this.ConfigManager = new ConfigurationManager<OpenIdConnectConfiguration>(CasEnv.WellKnownConfigUrl,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever() { RequireHttps = false });
        }

        private ILogger Logger { get; }
        public ConfigurationManager<OpenIdConnectConfiguration> ConfigManager { get; }

        public static bool IsTokenExpired(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);
            return (DateTime.UtcNow > jwt.Payload.ValidTo.ToUniversalTime());
        }

        public async Task<JwtSecurityToken> ValidateToken(string token)
        {

            // get the validation-certificates
            var config = await ConfigManager.GetConfigurationAsync();

            // parameters to validate
            var handler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuer = CasEnv.Issuer,
                ValidateAudience = true,
                ValidAudience = CasEnv.Audience,
                ValidateLifetime = true,
                IssuerSigningKeys = config.SigningKeys
            };

            // validate all previously defined parameters
            SecurityToken validatedSecurityToken = null;
            handler.ValidateToken(token, validationParameters, out validatedSecurityToken);
            JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;

            return validatedJwt;
        }

        public static string ReissueToken(string token)
        {
            using (var client = new WebClient())
            {
                if (!string.IsNullOrEmpty(CasEnv.Proxy)) client.Proxy = new WebProxy(CasEnv.Proxy);
                NameValueCollection data = new NameValueCollection();
                data.Add("token", token);
                byte[] response = client.UploadValues(CasEnv.ReissueUrl, data);
                string reissued = Encoding.UTF8.GetString(response);
                return reissued;
            }
        }

    }

}

