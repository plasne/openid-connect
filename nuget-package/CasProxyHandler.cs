
using System.Net;
using System.Net.Http;

namespace CasAuth
{

    public class CasProxyHandler : HttpClientHandler
    {

        public CasProxyHandler()
        {
            Proxy = (!string.IsNullOrEmpty(CasEnv.Proxy)) ? new WebProxy(CasEnv.Proxy, true) : null;
            UseProxy = (!string.IsNullOrEmpty(CasEnv.Proxy));
        }

    }

}