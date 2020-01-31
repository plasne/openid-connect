
using System.Collections.Generic;
using System.Security.Claims;

namespace CasAuth
{

    public static class CasListOfClaimsExtensions
    {

        public static Dictionary<string, string> ToDictionary(this IEnumerable<Claim> claims)
        {
            var dict = new Dictionary<string, string>();
            foreach (var claim in claims)
            {
                switch (claim.Type)
                {
                    case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":
                        dict.Add("name", claim.Value);
                        break;
                    case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
                        dict.Add("email", claim.Value);
                        break;
                    case "http://schemas.microsoft.com/ws/2008/06/identity/claims/role":
                        dict.Add("role", claim.Value);
                        break;
                    default:
                        dict.Add(claim.Type, claim.Value);
                        break;
                }
            }
            return dict;
        }

        public static void Add(this List<Claim> claims, string key, string value)
        {
            switch (key)
            {
                case "name":
                    claims.Add(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", value));
                    return;
                case "email":
                    claims.Add(new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", value));
                    return;
                case "role":
                case "roles":
                    claims.Add(new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", value));
                    return;
                default:
                    claims.Add(new Claim(key, value));
                    return;
            }
        }




    }

}