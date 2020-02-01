using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System;

namespace CasAuth
{

    public static class CasListOfClaimsExtensions
    {

        public static string Name(this IEnumerable<Claim> claims)
        {
            return claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")?.Value;
        }

        public static string Email(this IEnumerable<Claim> claims)
        {
            return claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")?.Value;
        }

        public static string EmailOrName(this IEnumerable<Claim> claims)
        {
            return claims.Email() ?? claims.Name();
        }

        public static IEnumerable<string> Roles(this IEnumerable<Claim> claims)
        {
            return claims.Where(c => c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role").Select(c => c.Value).Distinct();
        }

        public static bool HasRole(this IEnumerable<Claim> claims, string role)
        {
            return claims.Roles().FirstOrDefault(r => string.Compare(r, role, StringComparison.InvariantCultureIgnoreCase) == 0) != null;
        }

        public static bool IsAdmin(this IEnumerable<Claim> claims)
        {
            return claims.HasRole(CasEnv.RoleForAdmin);
        }

        public static bool IsService(this IEnumerable<Claim> claims)
        {
            return claims.HasRole(CasEnv.RoleForService);
        }

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

        public static IEnumerable<Claim> Distinct(this IEnumerable<Claim> claims)
        {
            return claims.GroupBy(c => c.Type + "=" + c.Value).Select(g => g.First());
        }




    }

}