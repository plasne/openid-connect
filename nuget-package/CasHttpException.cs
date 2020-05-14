
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

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

        public Task Apply(HttpResponse response)
        {
            response.Redirect(this.Redirect.ToString());
            response.StatusCode = this.StatusCode;
            return response.WriteAsync(this.Message);
        }

    }

}
