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
using System.Net.Http;
using System.Collections.Generic;

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

        public static async Task<string> ReissueToken(HttpClient httpClient, string token)
        {
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri(CasEnv.ReissueUrl),
                Method = HttpMethod.Post
            })
            {
                using (request.Content = new FormUrlEncodedContent(new[] {
                    new KeyValuePair<string, string>("token", token)
                }))
                {
                    using (var response = await httpClient.SendAsync(request))
                    {
                        var raw = await response.Content.ReadAsStringAsync();
                        if (!response.IsSuccessStatusCode)
                        {
                            throw new Exception($"CasTokenValidator.ReissueToken: HTTP {(int)response.StatusCode} - {raw}");
                        }
                        return raw;
                    }
                }
            };
        }

    }

}

