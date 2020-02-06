using System.Net.Http;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace CasAuth
{

    public class CasIntPropogateHeadersOptions
    {
        public List<string> Headers = new List<string>() { "X-IDENTITY", "X-EMAIL", "X-NAME", "X-ROLES", "X-CORRELATION" };
    }

    public class CasIntPropogateHeaders : DelegatingHandler
    {

        public CasIntPropogateHeaders(IHttpContextAccessor httpContextAccessor, CasIntPropogateHeadersOptions options = null)
        {
            this.HttpContextAccessor = httpContextAccessor;
            this.Options = options ?? new CasIntPropogateHeadersOptions();
        }

        private IHttpContextAccessor HttpContextAccessor { get; }
        private CasIntPropogateHeadersOptions Options { get; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var headers = this.HttpContextAccessor?.HttpContext?.Request?.Headers;
            if (headers != null && this.Options?.Headers != null)
            {
                foreach (var name in this.Options.Headers)
                {
                    if (headers.ContainsKey(name))
                    {
                        // propogate
                        request.Headers.Add(name, (string)headers[name]);
                    }
                    else if (string.Compare(name, "X-IDENTITY", StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        // propogate x-identity from claims if necessary
                        var user = this.HttpContextAccessor?.HttpContext?.User;
                        if (user != null)
                        {
                            var dict = user.Claims.FilterToSignificant().ToDictionary(i => (i.ShortType(), i.Value));
                            request.Headers.Add(name, JsonConvert.SerializeObject(dict));
                        }
                    }
                    else if (string.Compare(name, "X-CORRELATION", StringComparison.InvariantCultureIgnoreCase) == 0)
                    {
                        // start correlation id if one wasn't provided
                        request.Headers.Add(name, Guid.NewGuid().ToString());
                    }
                }
            }
            return await base.SendAsync(request, cancellationToken);
        }
    }

}