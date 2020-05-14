using System.Collections.Generic;
using System.Threading.Tasks;
using CasAuth;

namespace auth
{

    public class StoreAuthCodes : ICasAuthCodeReceiver
    {

        public IEnumerable<string> GetScopes()
        {
            return new string[] { "new_scope_1", "new_scope_2" };
        }

        public Task<IEnumerable<string>> GetScopesAsync()
        {
            throw new System.NotImplementedException();
        }

        public void Receive(string scope, string accessToken, string refreshToken)
        {
            throw new System.NotImplementedException();
        }

        public Task ReceiveAsync(string scope, string accessToken, string refreshToken)
        {
            // store in database
            return Task.CompletedTask;
        }

    }

}