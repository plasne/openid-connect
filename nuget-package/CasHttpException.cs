
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

        public Task Apply(HttpContext context)
        {
            var logger = context.RequestServices.GetService<ILogger<CasClientAuthMiddleware>>();
            logger.LogError(this, $"CasHttpException in {context.Request.Path}...");
            if (Redirect != null) context.Response.Redirect(this.Redirect.ToString());
            context.Response.StatusCode = this.StatusCode;
            return context.Response.WriteAsync(this.Message);
        }

    }

    public static class ExceptionExtensions
    {

        public static Task Apply(this Exception exception, HttpContext context)
        {
            var logger = context.RequestServices.GetService<ILogger<CasClientAuthMiddleware>>();
            logger.LogError(exception, $"Exception in {context.Request.Path}...");
            context.Response.StatusCode = 500;
            return context.Response.WriteAsync("internal server error");
        }

    }

}
