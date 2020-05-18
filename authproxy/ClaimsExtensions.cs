using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System;

namespace authproxy
{

    public static class ClaimsExtensions
    {

        /// <summary>
        /// AddLong() adds a claim using the fully qualified schema name for the key if it is
        /// "name", "email", "role", or "roles". This should typically only be used when defining
        /// claims for an IIdentity object. This is most useful because the schema for roles can
        /// be matched for requirements.
        /// </summary>
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





    }

}