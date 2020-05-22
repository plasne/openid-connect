using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System;

namespace CasAuth
{

    public static class CasClaimsExtensions
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
            return claims.HasRole(CasConfig.RoleForAdmin);
        }

        public static bool IsService(this IEnumerable<Claim> claims)
        {
            return claims.HasRole(CasConfig.RoleForService);
        }

        public static List<Claim> FilterToSignificant(this IEnumerable<Claim> claims)
        {
            var filter = new string[] { "xsrf", "old", "exp", "iss", "aud" };
            var filtered = claims.ToList();
            filtered.RemoveAll(c => filter.Contains(c.Type));
            return filtered;
        }

        public static string ShortType(this Claim claim)
        {
            switch (claim.Type)
            {
                case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":
                    return "name";
                case "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
                    return "email";
                case "http://schemas.microsoft.com/ws/2008/06/identity/claims/role":
                    return "role";
                default:
                    return claim.Type;
            }
        }

        public static string LongType(this Claim claim)
        {
            switch (claim.Type)
            {
                case "name":
                    return "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
                case "email":
                    return "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
                case "role":
                case "roles":
                    return "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
                default:
                    return claim.Type;
            }
        }

        public static void AddLong(this List<Claim> claims, string key, string value)
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

        public static void AddShort(this List<Claim> claims, string key, string value)
        {
            if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(value)) return;

            // trim the value
            value = value.Trim();

            // add if not a duplicate
            var existing = claims.Find(c => string.Compare(c.Type, key, StringComparison.InvariantCultureIgnoreCase) == 0 &&
                string.Compare(c.Value, value, StringComparison.InvariantCultureIgnoreCase) == 0);
            if (existing == null) claims.Add(new Claim(key, value));

        }




    }

}