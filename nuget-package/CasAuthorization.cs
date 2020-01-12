using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace CasAuth
{

    public class CasXsrfRequirement : IAuthorizationRequirement { }

    public class CasXsrfHandler : AuthorizationHandler<CasXsrfRequirement>
    {

        public CasXsrfHandler(ILogger<CasXsrfHandler> logger, CasTokenValidator validator, IHttpContextAccessor contextAccessor)
        {
            this.Logger = logger;
            this.Validator = validator;
            this.ContextAccessor = contextAccessor;
        }

        private ILogger Logger { get; }
        private CasTokenValidator Validator { get; }
        private IHttpContextAccessor ContextAccessor;

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, CasXsrfRequirement requirement)
        {
            try
            {

                // if there is no requirement for XSRF, then don't check for it
                if (!CasEnv.VerifyXsrfInHeader && !CasEnv.VerifyXsrfInCookie)
                {
                    context.Succeed(requirement);
                    return Task.CompletedTask;
                }

                // get the identity of the authenticated user
                var identity = context.User.Identity as ClaimsIdentity;
                if (identity == null) throw new Exception("identity not found");
                if (!identity.IsAuthenticated) throw new Exception("user is not authenticated");

                // if this is a service account, no XSRF is required
                var typ = identity.Claims.FirstOrDefault(c => c.Type == "typ");
                if (typ != null && typ.Value == "service")
                {
                    context.Succeed(requirement);
                    return Task.CompletedTask;
                }

                // get the XSRF-TOKEN (header, cookie)
                string code = null;
                if (CasEnv.VerifyXsrfInHeader)
                {
                    code = ContextAccessor.HttpContext.Request.Headers["X-XSRF-TOKEN"];
                }
                if (CasEnv.VerifyXsrfInCookie && string.IsNullOrEmpty(code))
                {
                    code = ContextAccessor.HttpContext.Request.Cookies["XSRF-TOKEN"];
                }
                if (string.IsNullOrEmpty(code)) throw new Exception("XSRF code not found");

                // validate the signature if signed
                //  NOTE: it will be signed if the source claim was accessible via JavaScript
                if (!CasEnv.RequireHttpOnlyOnUserCookie)
                {
                    var validate = this.Validator.ValidateToken(code);
                    validate.Wait();
                    var validated = validate.Result;
                    var codeclaim = validated.Payload.Claims.FirstOrDefault(c => c.Type == "code");
                    if (codeclaim == null) throw new Exception("xsrf signed token did not contain a code");
                    code = codeclaim.Value;
                }

                // verify that it matches the XSRF claim
                var xsrfclaim = identity.FindFirst(c => c.Type == "xsrf");
                if (xsrfclaim == null) throw new Exception("xsrf claim not found");
                if (code != xsrfclaim.Value) throw new Exception("xsrf claim does not match code");

                context.Succeed(requirement);
            }
            catch (Exception e)
            {
                Logger.LogError(e, "authorization failure");
                context.Fail();
            }
            return Task.CompletedTask;
        }
    }

}