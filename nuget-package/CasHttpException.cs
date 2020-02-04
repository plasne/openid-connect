
using System;

namespace CasAuth
{

    public class CasHttpException : Exception
    {

        public CasHttpException(int code, string msg) : base(msg)
        {
            this.StatusCode = code;
        }

        public int StatusCode { get; set; }
    }

}
