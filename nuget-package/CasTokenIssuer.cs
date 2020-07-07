using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using System.Net.Http;
using NetBricks;

namespace CasAuth
{

    public class CasTokenIssuer
    {

        public CasTokenIssuer(
            ILogger<CasTokenIssuer> logger,
            IHttpClientFactory httpClientFactory,
            IConfig config
        )
        {
            this.Logger = logger;
            this.HttpClient = httpClientFactory.CreateClient("cas");
            this.Config = config as CasConfig;
            if (this.Config == null) throw new Exception("CasTokenIssuer: CasConfig was not found in the IServiceCollection.");
        }

        private ILogger Logger { get; }
        private HttpClient HttpClient { get; }
        private CasConfig Config { get; }

        private X509SigningCredentials _signingCredentials;

        public async Task<X509SigningCredentials> GetSigningCredentials()
        {
            if (_signingCredentials == null)
            {
                var privateKey = await Config.PrivateKey();
                var bytes = Convert.FromBase64String(privateKey);
                var privateKeyPassword = await Config.PrivateKeyPassword();
                var certificate = new X509Certificate2(bytes, privateKeyPassword);
                _signingCredentials = new X509SigningCredentials(certificate, SecurityAlgorithms.RsaSha256);
            }
            return _signingCredentials;
        }

        private List<X509Certificate2> _validationCertificates;

        public async Task<List<X509Certificate2>> GetValidationCertificates()
        {
            if (_validationCertificates == null)
            {
                _validationCertificates = new List<X509Certificate2>();

                // attempt to get certificates indexed 0-3 at the same time
                var tasks = new List<Task<string>>();
                for (int i = 0; i < 4; i++)
                {
                    tasks.Add(Config.PublicCert(i));
                }

                // wait for all the tasks to complete
                await Task.WhenAll(tasks.ToArray());

                // add to certificates
                foreach (var task in tasks)
                {
                    if (!string.IsNullOrEmpty(task.Result))
                    {
                        byte[] bytes = GetBytesFromPEM(task.Result, "CERTIFICATE");
                        var x509 = new X509Certificate2(bytes);
                        _validationCertificates.Add(x509);
                    }
                }

                // make sure there is at least 1
                if (_validationCertificates.Count() < 1) throw new Exception("there are no PUBLIC_CERT_# variables defined");

            }
            return _validationCertificates;
        }

        private static byte[] GetBytesFromPEM(string pemString, string section = "CERTIFICATE")
        {
            var header = String.Format("-----BEGIN {0}-----", section);
            var footer = String.Format("-----END {0}-----", section);
            var start = pemString.IndexOf(header, StringComparison.Ordinal);
            if (start < 0) return null;
            start += header.Length;
            var end = pemString.IndexOf(footer, start, StringComparison.Ordinal) - start;
            if (end < 0) return null;
            string body = pemString.Substring(start, end).Trim();
            return Convert.FromBase64String(body);
        }

        public void ClearSigningKey()
        {
            Config.RemoveFromCache("PRIVATE_KEY");
            Config.RemoveFromCache("PRIVATE_KEY_PASSWORD");
            _signingCredentials = null;
        }

        public void ClearValidationCertificates()
        {
            Config.RemoveFromCache("PUBLIC_CERT_0");
            Config.RemoveFromCache("PUBLIC_CERT_1");
            Config.RemoveFromCache("PUBLIC_CERT_2");
            Config.RemoveFromCache("PUBLIC_CERT_3");
            _validationCertificates = null;
        }

        public async Task<string> IssueToken(List<Claim> claims)
        {

            // validate that the claims are legitimate
            if (claims.FirstOrDefault(c => c.Type == "iss") != null) throw new Exception("claim cannot contain an issuer");
            if (claims.FirstOrDefault(c => c.Type == "aud") != null) throw new Exception("claim cannot contain an audience");
            if (claims.FirstOrDefault(c => c.Type == "exp") != null) throw new Exception("claim cannot contain an expiration");

            // add the max-age if appropriate
            if (CasConfig.JwtMaxDuration > 0 && claims.FirstOrDefault(c => c.Type == "old") == null)
            {
                claims.Add(new Claim("old", new DateTimeOffset(DateTime.UtcNow).AddMinutes(CasConfig.JwtMaxDuration).ToUnixTimeSeconds().ToString()));
            }

            // determine the signing duration
            var duration = (claims.IsService()) ? CasConfig.JwtServiceDuration : CasConfig.JwtDuration;

            // get the signing creds
            var signingCredentials = await GetSigningCredentials();

            // generate the token
            var jwt = new JwtSecurityToken(
                issuer: CasConfig.Issuer,
                audience: CasConfig.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(duration),
                signingCredentials: signingCredentials);

            // serialize
            try
            {
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                return handler.WriteToken(jwt);
            }
            catch (Exception e)
            {
                if (e.Message.Contains("The system cannot find the file specified"))
                {
                    throw new Exception("The User Profile is not available - https://github.com/projectkudu/kudu/wiki/Configurable-settings#the-system-cannot-find-the-file-specified-issue-with-x509certificate2", e);
                }
                else
                {
                    throw;
                }
            }

        }

        public async Task<string> IssueXsrfToken(string code)
        {

            // add the claims
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("code", code));

            // get the signing creds
            var signingCredentials = await GetSigningCredentials();

            // generate the token
            var jwt = new JwtSecurityToken(
                issuer: CasConfig.Issuer,
                audience: CasConfig.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(CasConfig.JwtMaxDuration).AddMinutes(60), // good beyond the max-duration
                signingCredentials: signingCredentials);

            // serialize
            try
            {
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                return handler.WriteToken(jwt);
            }
            catch (Exception e)
            {
                if (e.Message.Contains("The system cannot find the file specified"))
                {
                    throw new Exception("The User Profile is not available - https://github.com/projectkudu/kudu/wiki/Configurable-settings#the-system-cannot-find-the-file-specified-issue-with-x509certificate2", e);
                }
                else
                {
                    throw;
                }
            }

        }

        public async Task<JwtSecurityToken> ValidateToken(string token)
        {

            // get keys from certificates
            var certs = await GetValidationCertificates();
            var keys = certs.Select(c => new X509SecurityKey(c));

            // parameters to validate
            var handler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuer = CasConfig.Issuer,
                ValidateAudience = true,
                ValidAudience = CasConfig.Audience,
                ValidateLifetime = true,
                IssuerSigningKeys = keys
            };

            // validate all previously defined parameters
            SecurityToken validatedSecurityToken = null;
            handler.ValidateToken(token, validationParameters, out validatedSecurityToken);
            JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;

            return validatedJwt;
        }

        public async Task<JwtSecurityToken> IsTokenExpiredButEligibleForRenewal(string token)
        {

            // read the token
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);

            // shortcut if not expired
            if (DateTime.UtcNow < jwt.Payload.ValidTo.ToUniversalTime()) throw new CasHttpException(400, "token is not expired");

            // make sure it is not a service account
            if (jwt.Payload.Claims.IsService()) throw new CasHttpException(403, "only user tokens can be reissued");

            // get keys from certificates
            var certs = await GetValidationCertificates();
            var keys = certs.Select(c => new X509SecurityKey(c));

            // validate everything but the expiry
            SecurityToken validatedSecurityToken = null;
            try
            {
                handler.ValidateToken(token, new TokenValidationParameters
                {
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidateIssuer = true,
                    ValidIssuer = CasConfig.Issuer,
                    ValidateAudience = true,
                    ValidAudience = CasConfig.Audience,
                    ValidateLifetime = false, // we want to validate everything but the lifetime
                    IssuerSigningKeys = keys
                }, out validatedSecurityToken);
            }
            catch (Exception e)
            {
                throw new CasHttpException(400, "token cannot be validated (excepting lifetime) - " + e.Message);
            }
            JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;

            // tokens are only eligible up to a defined age
            var old = jwt.Payload.FirstOrDefault(claim => claim.Key == "old");
            if (old.Value == null) return validatedJwt; // no max-age, so it is eligible
            if (!long.TryParse((string)old.Value, out long oldAsLong)) throw new Exception("token max-age cannot be determined");
            var max = DateTimeOffset.FromUnixTimeSeconds(oldAsLong).UtcDateTime;
            if (DateTime.UtcNow < max)
            {
                return validatedJwt;
            }
            else
            {
                throw new CasHttpException(403, "token is too old to renew");
            }

        }

    }

}