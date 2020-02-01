using CasAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace internal_svc.Controllers
{

    [ApiController]
    [Route("[controller]")]
    public class SampleController : ControllerBase
    {

        [Authorize]
        [HttpGet, Route("name")]
        public ActionResult<string> GetName()
        {
            return User.Claims.Name();
        }
    }
}
