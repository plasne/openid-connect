using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;

namespace authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class IdentityController : ControllerBase
    {

        [Authorize]
        [HttpGet, Route("me")]
        public ActionResult<dynamic> Me()
        {
            string authorization = Request.Headers["Authorization"];
            string token = authorization.Replace("Bearer ", "");
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);
            return Ok(jwt.Payload);
        }

        [AllowAnonymous]
        [HttpGet, Route("version")]
        public ActionResult<string> Version()
        {
            return "v1.0.0";
        }

    }

}
