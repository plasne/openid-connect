using System.Threading.Tasks;
using System.Collections.Generic;
using System;

namespace CasAuth
{

    public interface ICasAuthCodeReceiver
    {

        IEnumerable<string> GetScopes();

        Task<IEnumerable<string>> GetScopesAsync();

        void Receive(string scope, string accessToken, string refreshToken);

        Task ReceiveAsync(string scope, string accessToken, string refreshToken);

    }

    public static class ICasAuthCodeReceiverExtensions
    {

        public static async Task<List<string>> GetAllScopes(this ICasAuthCodeReceiver receiver)
        {
            var list = new List<string>();
            try
            {
                list.AddRange(receiver.GetScopes());
            }
            catch (NotImplementedException)
            {
                // ignore, it is OK to not be implemented
            }
            try
            {
                list.AddRange(await receiver.GetScopesAsync());
            }
            catch (NotImplementedException)
            {
                // ignore, it is OK to not be implemented
            }
            return list;
        }

        public static async Task ReceiveAll(this ICasAuthCodeReceiver receiver, string scope, string accessToken, string refreshToken)
        {
            try
            {
                receiver.Receive(scope, accessToken, refreshToken);
            }
            catch (NotImplementedException)
            {
                // ignore, it is OK to not be implemented
            }
            try
            {
                await receiver.ReceiveAsync(scope, accessToken, refreshToken);
            }
            catch (NotImplementedException)
            {
                // ignore, it is OK to not be implemented
            }
        }

    }

}