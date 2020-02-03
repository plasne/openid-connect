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
            if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(value)) return;

            // normalize the key
            switch (key)
            {
                case "name":
                    key = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
                    break;
                case "email":
                    key = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
                    break;
                case "role":
                case "roles":
                    key = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
                    break;
            }

            // trim the value
            value = value.Trim();

            // add if not a duplicate
            var existing = claims.Find(c => string.Compare(c.Type, key, StringComparison.InvariantCultureIgnoreCase) == 0 &&
                string.Compare(c.Value, value, StringComparison.InvariantCultureIgnoreCase) == 0);
            if (existing == null) claims.Add(new Claim(key, value));

        }





    }

}