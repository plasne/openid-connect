# Custom Claims

Adding custom claims is done by implementing a class that inherits from ICasClaimsBuilder. You will implement either AddClaims() or AddClaimsAsync() leaving the other throwing a NotImplementedException. For example...

```c#
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using CasAuth;

namespace auth
{

    public class AddClaimsFromUserDb : ICasClaimsBuilder
    {

        public AddClaimsFromUserDb(ICasConfig config)
        {
            this.Config = config;
        }

        private ICasConfig Config { get; set; }

        public async Task AddClaimsAsync(IEnumerable<Claim> inClaims, List<Claim> outClaims)
        {

            // get a secret, potentially even from key vault
            string connstring = await Config.GetString("USER_SQL_CONNSTRING");

            // implement a connection to SQL to read claims

            // add claims
            outClaims.AddShort("color", "yellow");
            outClaims.AddShort("role", "admin");

        }

        void ICasClaimsBuilder.AddClaims(IEnumerable<Claim> inClaims, List<Claim> outClaims)
        {
            throw new System.NotImplementedException();
        }
    }

}
```

Make sure in the startup that you register the builder...

```c#
public void ConfigureServices(IServiceCollection services)
{
    services.AddSingleton<ICasClaimsBuilder, AddClaimsFromUserDb>();
    services.AddCasServerAuth();
    services.AddControllers();
}
```

The above example shows adding a custom claim of "color = yellow" as well as an admin role.

-   inClaims - This is an IEnumerable of Claims that were found in the OIDC id_token.

-   outClaims - This is a List of Claims that will be encoded into the JWT payload. This will include the claims that were extracted or derived from the OIDC id_token. While generally you would add claims, it is possible to remove them as well.

The AddShort() method should always be used instead of the AddLong() method. AddShort() adds claims with the name you gave them whereas AddLong() adds the claims with their fully qualified schema name. The fully qualified name is only used for populating IIdentity objects.