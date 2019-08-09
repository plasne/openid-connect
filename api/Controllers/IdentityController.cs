using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Collections.Generic;
using System.Security.Claims;

namespace authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class IdentityController : ControllerBase
    {

        [Authorize]
        [HttpGet, Route("me")]
        public ActionResult<Dictionary<string, object>> Me()
        {

            // read from the token instead of claims since it has the original claim names
            string authorization = Request.Headers["Authorization"];
            string token = authorization.Replace("Bearer ", "");
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);

            // filter the claims
            var filter = new string[] { "xsrf", "old", "exp", "iss", "aud" };
            var filtered = jwt.Payload.Claims.ToList();
            filtered.RemoveAll(c => filter.Contains(c.Type));

            // project to a dictionary
            var projected = new Dictionary<string, object>();
            foreach (var claim in filtered)
            {
                if (projected.ContainsKey(claim.Type))
                {
                    var obj = projected[claim.Type];
                    if (obj is string)
                    {
                        projected[claim.Type] = new List<string>() { (string)obj, claim.Value };
                    }
                    else
                    {
                        ((List<string>)projected[claim.Type]).Add(claim.Value);
                    }
                }
                else
                {
                    projected.Add(claim.Type, claim.Value);
                }
            }

            return Ok(projected);
        }

        [AllowAnonymous]
        [HttpGet, Route("version")]
        public ActionResult<string> Version()
        {
            return "v1.0.0";
        }

    }

}
