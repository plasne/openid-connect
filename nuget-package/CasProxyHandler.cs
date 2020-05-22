
using System.Net;
using System.Net.Http;

namespace CasAuth
{

    public class CasProxyHandler : HttpClientHandler
    {

        public CasProxyHandler()
        {
            Proxy = (!string.IsNullOrEmpty(CasConfig.Proxy)) ? new WebProxy(CasConfig.Proxy, true) : null;
            UseProxy = (!string.IsNullOrEmpty(CasConfig.Proxy));
        }

    }

}