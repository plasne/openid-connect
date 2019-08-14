using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace authentication.Controllers
{
    [Route("api/[controller]")]
    [Authorize("admin")]
    [ApiController]
    public class AdminController : ControllerBase
    {

        [HttpPost, Route("clear-cache")]
        public ActionResult ClearCache([FromForm] string scope, [FromServices] TokenValidator tokenValidator)
        {
            if (!string.IsNullOrEmpty(scope))
            {
                var scopes = scope.Split(',').Select(id => id.Trim());

                // clear openid-configuration
                if (scopes.Contains("openid-configuration"))
                {
                    tokenValidator.ConfigManager.RequestRefresh();
                }

            }
            return Ok();
        }

        [HttpGet, Route("validation-thumbprints")]
        public async Task<ActionResult<List<string>>> ValidationThumbprints([FromServices] TokenValidator tokenValidator)
        {
            var list = new List<string>();
            var config = await tokenValidator.ConfigManager.GetConfigurationAsync();
            foreach (var key in config.SigningKeys)
            {
                if (!list.Contains(key.KeyId)) list.Add(key.KeyId);
            }
            return Ok(list);
        }

    }

}
