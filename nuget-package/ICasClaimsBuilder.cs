using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Claims;
using System;

namespace CasAuth
{

    public interface ICasClaimsBuilder
    {

        void AddClaims(IEnumerable<Claim> inClaims, List<Claim> outClaims);

        Task AddClaimsAsync(IEnumerable<Claim> inClaims, List<Claim> outClaims);

    }

    public static class ICasClaimsBuilderExtensions
    {

        public static async Task AddAllClaims(this ICasClaimsBuilder builder, IEnumerable<Claim> inClaims, List<Claim> outClaims)
        {
            try
            {
                builder.AddClaims(inClaims, outClaims);
            }
            catch (NotImplementedException)
            {
                // ignore, it is OK to not be implemented
            }
            try
            {
                await builder.AddClaimsAsync(inClaims, outClaims);
            }
            catch (NotImplementedException)
            {
                // ignore, it is OK to not be implemented
            }
        }

    }


}

