using System;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace CasAuth
{

    public class CasXsrfRequirement : IAuthorizationRequirement
    { }

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

        public async Task<bool> IsAuthorized(IIdentity iidentity)
        {
            try
            {
                Logger.LogDebug("CasXsrfHandler: start authorization check for XSRF...");

                // if there is no requirement for XSRF, then don't check for it
                if (!CasEnv.VerifyXsrfInHeader && !CasEnv.VerifyXsrfInCookie)
                {
                    Logger.LogDebug("CasXsrfHandler: neither VERIFY_XSRF_IN_HEADER or VERIFY_XSRF_IN_COOKIE are \"true\" so the authorization check is a success.");
                    return true;
                }

                // get the identity of the authenticated user
                var identity = iidentity as ClaimsIdentity;
                if (identity == null || !identity.IsAuthenticated)
                {
                    Logger.LogDebug("CasXsrfHandler: authentication failed, so the authorization check is a failure.");
                    throw new Exception("user is not authenticated");
                }

                // if this is a service account, no XSRF is required
                if (identity.Claims.IsService())
                {
                    Logger.LogDebug("CasXsrfHandler: the identity is a service account, XSRF is not required, so the authorization check is a success.");
                    return true;
                }

                // get the XSRF-TOKEN (header, cookie)
                string code = null;
                if (CasEnv.VerifyXsrfInHeader)
                {
                    code = ContextAccessor.HttpContext.Request.Headers["X-XSRF-TOKEN"];
                    Logger.LogDebug($"CasXsrfHandler: the XSRF token was obtained from a header as \"{code}\"...");
                }
                if (CasEnv.VerifyXsrfInCookie && string.IsNullOrEmpty(code))
                {
                    code = ContextAccessor.HttpContext.Request.Cookies["XSRF-TOKEN"];
                    Logger.LogDebug($"CasXsrfHandler: the XSRF token was obtained from a cookie as \"{code}\"...");
                }
                if (string.IsNullOrEmpty(code))
                {
                    Logger.LogDebug("CasXsrfHandler: the XSRF code was null or empty, so the authorization check is a failure.");
                    throw new Exception("XSRF code not found");
                }

                // validate the signature if signed
                //  NOTE: it will be signed if the source claim was accessible via JavaScript
                if (!CasEnv.RequireHttpOnlyOnUserCookie)
                {
                    Logger.LogDebug($"CasXsrfHandler: the XSRF token is signed, it will be verified...");
                    var validated = await this.Validator.ValidateToken(code);
                    var codeclaim = validated.Payload.Claims.FirstOrDefault(c => c.Type == "code");
                    if (codeclaim == null)
                    {
                        Logger.LogDebug("CasXsrfHandler: the signed XSRF token did not contain a code, so the authorization check is a failure.");
                        throw new Exception("xsrf signed token did not contain a code");
                    }
                    code = codeclaim.Value;
                    Logger.LogDebug($"CasXsrfHandler: the XSRF token is signed, it was verified successfully as extracted as \"{code}\"...");
                }

                // verify that it matches the XSRF claim
                var xsrfclaim = identity.FindFirst(c => c.Type == "xsrf");
                if (xsrfclaim == null)
                {
                    Logger.LogDebug("CasXsrfHandler: the identity did not contain an XSRF code, so the authorization check is a failure.");
                    throw new Exception("xsrf claim not found");
                }
                if (code != xsrfclaim.Value)
                {
                    Logger.LogDebug($"CasXsrfHandler: the XSRF code did not match, expected \"{xsrfclaim.Value}\", received \"{code}\", so the authorization check is a failure.");
                    throw new Exception("xsrf claim does not match code");
                }

                // success
                Logger.LogDebug("CasXsrfHandler: the codes matched, so the authorization check is a success.");
                return true;

            }
            catch (Exception e)
            {
                Logger.LogWarning(e, "authorization failure");
                return false;
            }
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, CasXsrfRequirement requirement)
        {
            var auth = await IsAuthorized(context.User?.Identity);
            if (auth)
            {
                context.Succeed(requirement);
            }
            else
            {
                context.Fail();
            }
        }





    }

}