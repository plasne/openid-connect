using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Collections.Generic;

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

            // filter the claims
            var filter = new string[] { "xsrf", "old", "exp", "iss", "aud" };
            var filtered = User.Claims.ToList();
            filtered.RemoveAll(c => filter.Contains(c.Type) || c.Type.StartsWith("http://schemas.microsoft.com/"));

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
