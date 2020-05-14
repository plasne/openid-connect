using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Linq;

namespace api.Controllers
{

    public class MenuItem
    {
        public string Name { get; set; }
        public string Link { get; set; }
    }

    [ApiController]
    public class ApiController : ControllerBase
    {

        public ApiController(ILogger<ApiController> logger)
        {
            this.Logger = logger;
        }

        private ILogger<ApiController> Logger { get; }

        public static string LoginLink
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("LOGIN_LINK") ??
                    "https://link-undefined";
            }
        }

        public static string PortalLink
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("PORTAL_LINK") ??
                    "https://link-undefined";
            }
        }

        [HttpGet("/login-link")]
        public ActionResult<string> GetLoginLink()
        {
            return Ok(LoginLink);
        }

        [Authorize]
        [HttpGet("/menu")]
        public ActionResult<List<MenuItem>> GetMenu()
        {
            var list = new List<MenuItem>();
            list.Add(new MenuItem()
            {
                Name = "Portal",
                Link = PortalLink
            });
            return Ok(list);
        }

        [Authorize]
        [HttpGet("/stuff")]
        public ActionResult<List<string>> GetStuff()
        {
            var list = new List<string>();
            list.Add("stuff-1");
            list.Add("stuff-2");
            list.Add("stuff-3");
            return Ok(list);
        }

    }

}
