using System;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Specialized;
using System.Text;
using Microsoft.Extensions.Logging;

public class TokenValidator
{

    public TokenValidator(ILoggerFactory factory)
    {
        this.Logger = factory.CreateLogger<TokenValidator>();
    }

    private ILogger Logger { get; }

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

    public static string PublicCertificateUrl
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("PUBLIC_CERTIFICATE_URL");
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

    private X509SecurityKey _validationKey;

    public X509SecurityKey ValidationKey
    {
        get
        {
            if (_validationKey == null)
            {

                // get the certificate
                using (var client = new WebClient())
                {
                    string raw = client.DownloadString(new Uri(PublicCertificateUrl));
                    byte[] bytes = GetBytesFromPEM(raw, "CERTIFICATE");
                    var certificate = new X509Certificate2(bytes);
                    _validationKey = new X509SecurityKey(certificate);
                }

            }
            return _validationKey;
        }
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
        return Convert.FromBase64String(pemString.Substring(start, end));
    }

    public static bool IsTokenExpired(string token)
    {

        // read the token
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        return (DateTime.UtcNow > jwt.Payload.ValidTo.ToUniversalTime());

    }

    public static string ReissueToken(string token)
    {
        using (var client = new WebClient())
        {
            NameValueCollection data = new NameValueCollection();
            data.Add("token", token);
            byte[] response = client.UploadValues(ReissueUrl, data);
            string reissued = Encoding.UTF8.GetString(response);
            return reissued;
        }
    }

}