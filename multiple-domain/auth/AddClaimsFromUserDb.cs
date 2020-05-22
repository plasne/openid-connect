using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.Data.SqlClient;
using System.Data;
using CasAuth;
using System.Threading.Tasks;
using NetBricks;

namespace auth
{

    public class AddClaimsFromUserDb : ICasClaimsBuilder
    {

        public AddClaimsFromUserDb(IConfig config)
        {
            this.Config = config;
        }

        private IConfig Config { get; set; }

        public async Task AddClaimsAsync(IEnumerable<Claim> inClaims, List<Claim> outClaims)
        {
            var email = inClaims.FirstOrDefault(c => c.Type == "email");
            if (email != null)
            {
                // NOTE: Config.GetString() caches the response, so no worry about calling it many times
                string connstring = await Config.GetSecret<string>("USER_SQL_CONNSTRING");
                using (var conn = new SqlConnection(connstring))
                {
                    await conn.OpenAsync();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = "SELECT Org, IsAdmin FROM dbo.Users WHERE Email=@email";
                        cmd.Parameters.Add("email", SqlDbType.VarChar, 50).Value = email.Value;
                        using (var reader = await cmd.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                if (!reader.IsDBNull(0))
                                {
                                    outClaims.AddShort("org", (string)reader[0]);
                                }
                                if (!reader.IsDBNull(1) && (byte)reader[1] > 0)
                                {
                                    outClaims.AddShort("role", "admin");
                                }
                            }
                            else
                            {
                                throw new CasHttpException(403, $"email address \"{email.Value}\" was not found in the user database.");
                            }
                        }
                    }
                }
            }
            else
            {
                throw new CasHttpException(403, "no email address could be found in the identity_token.");
            }
        }

        void ICasClaimsBuilder.AddClaims(IEnumerable<Claim> inClaims, List<Claim> outClaims)
        {
            throw new System.NotImplementedException();
        }
    }

}