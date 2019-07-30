using System;
using System.Linq;
using Microsoft.Identity.Client;
using dotenv.net;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;

public class TokenValidator : TokenBase
{

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

    public static string AppHome
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("APP_HOME");
        }
    }

    public static string BaseDomain
    {
        get
        {
            return System.Environment.GetEnvironmentVariable("BASE_DOMAIN");
        }
    }

    public bool IsTokenExpired(string token)
    {

        // read the token
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        return (DateTime.UtcNow > jwt.Payload.ValidTo.ToUniversalTime());

    }

}