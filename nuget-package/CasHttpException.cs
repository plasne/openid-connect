
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace CasAuth
{

    public class CasHttpException : Exception
    {

        public CasHttpException(int code, string msg) : base(msg)
        {
            this.StatusCode = code;
        }

        public CasHttpException(Uri redirect, string msg) : base(msg)
        {
            this.Redirect = redirect;
        }

        public int StatusCode { get; set; }

        public Uri Redirect { get; set; }

    }

    public static class ExceptionExtensions
    {

        public static Task Apply(this Exception exception, HttpContext context)
        {
            var logger = context.RequestServices.GetService<ILogger<CasClientAuthMiddleware>>();
            var cas = exception as CasHttpException;
            if (cas != null)
            {
                logger.LogError(cas, $"CasHttpException in {context.Request.Path}...");
                if (cas.Redirect != null) context.Response.Redirect(cas.Redirect.ToString());
                context.Response.StatusCode = cas.StatusCode;
                return context.Response.WriteAsync(cas.Message);
            }
            else
            {
                logger.LogError(exception, $"Exception in {context.Request.Path}...");
                context.Response.StatusCode = 500;
                return context.Response.WriteAsync("internal server error");
            }
        }

    }

}
