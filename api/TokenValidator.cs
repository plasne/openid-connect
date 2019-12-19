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

public class TokenValidator
{

    public TokenValidator(ILoggerFactory factory)
    {
        this.Logger = factory.CreateLogger<TokenValidator>();
        this.ConfigManager = new ConfigurationManager<OpenIdConnectConfiguration>(TokenValidator.WellKnownConfigUrl,
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever() { RequireHttps = false });
    }

    private ILogger Logger { get; }
    public ConfigurationManager<OpenIdConnectConfiguration> ConfigManager { get; }

    public static string Issuer
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("ISSUER");
        }
    }

    public static string Audience
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("AUDIENCE");
        }
    }

    public static string WellKnownConfigUrl
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("WELL_KNOWN_CONFIG_URL");
        }
    }

    public static string ReissueUrl
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("REISSUE_URL");
        }
    }

    public static string[] AllowedOrigins
    {
        get
        {
            string origins = System.Environment.GetEnvironmentVariable("ALLOWED_ORIGINS");
            if (string.IsNullOrEmpty(origins)) return new string[] { };
            return origins.Split(',').Select(id => id.Trim()).ToArray();
        }
    }

    public static bool RequireSecureForCookies
    {
        get
        { // default is true
            string v = System.Environment.GetEnvironmentVariable("REQUIRE_SECURE_FOR_COOKIES");
            if (string.IsNullOrEmpty(v)) return true;
            string[] negative = new string[] { "no", "false", "0" };
            return (!negative.Contains(v));
        }
    }

    public static bool RequireHttpOnlyOnUserCookie
    {
        get
        { // default is true
            string v = System.Environment.GetEnvironmentVariable("REQUIRE_HTTPONLY_ON_USER_COOKIE");
            if (string.IsNullOrEmpty(v)) return true;
            string[] negative = new string[] { "no", "false", "0" };
            return (!negative.Contains(v.ToLower()));
        }
    }

    public static string BaseDomain
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("BASE_DOMAIN");
        }
    }

    public static bool VerifyTokenInHeader
    {
        get
        { // default is false
            string v = System.Environment.GetEnvironmentVariable("VERIFY_TOKEN_IN_HEADER");
            if (string.IsNullOrEmpty(v)) return false;
            string[] positive = new string[] { "yes", "true", "1" };
            return (positive.Contains(v.ToLower()));
        }
    }

    public static bool VerifyTokenInCookie
    {
        get
        { // default is true
            string v = System.Environment.GetEnvironmentVariable("VERIFY_TOKEN_IN_COOKIE");
            if (string.IsNullOrEmpty(v)) return true;
            string[] negative = new string[] { "no", "false", "0" };
            return (!negative.Contains(v));
        }
    }

    public static bool VerifyXsrfInHeader
    {
        get
        { // default is true
            string v = System.Environment.GetEnvironmentVariable("VERIFY_XSRF_IN_HEADER");
            if (string.IsNullOrEmpty(v)) return true;
            string[] negative = new string[] { "no", "false", "0" };
            return (!negative.Contains(v.ToLower()));
        }
    }

    public static bool VerifyXsrfInCookie
    {
        get
        { // default is false
            string v = System.Environment.GetEnvironmentVariable("VERIFY_XSRF_IN_COOKIE");
            if (string.IsNullOrEmpty(v)) return false;
            string[] positive = new string[] { "yes", "true", "1" };
            return (positive.Contains(v.ToLower()));
        }
    }

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
            ValidIssuer = Issuer,
            ValidateAudience = true,
            ValidAudience = Audience,
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
            if (!string.IsNullOrEmpty(Config.Proxy)) client.Proxy = new WebProxy(Config.Proxy);
            NameValueCollection data = new NameValueCollection();
            data.Add("token", token);
            byte[] response = client.UploadValues(ReissueUrl, data);
            string reissued = Encoding.UTF8.GetString(response);
            return reissued;
        }
    }

}