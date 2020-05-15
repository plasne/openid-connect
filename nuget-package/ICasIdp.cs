using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace CasAuth
{

    public interface ICasIdp
    {

        string Id { get; }

        Task Authorize(HttpContext context);

        Task Token(HttpContext context);

        Task Service(HttpContext context);

        Task<string> Reissue(string token);

    }

}