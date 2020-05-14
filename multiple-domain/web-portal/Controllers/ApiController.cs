using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Linq;
using CasAuth;
using System.Threading.Tasks;

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

        public ApiController(
            ILogger<ApiController> logger,
            IEnumerable<IAuthorizationHandler> authHandlers
        )
        {
            this.Logger = logger;
            this.CasXsrfHandler = authHandlers.OfType<CasXsrfHandler>().FirstOrDefault();
        }

        private ILogger<ApiController> Logger { get; }
        private CasXsrfHandler CasXsrfHandler { get; }

        public static string AppLink
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("APP_LINK") ??
                    "https://link-undefined";
            }
        }

        public static string OtherLink
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("OTHER_LINK") ??
                    "https://link-undefined";
            }
        }

        public static string LoginLink
        {
            get
            {
                return System.Environment.GetEnvironmentVariable("LOGIN_LINK") ??
                    "https://link-undefined";
            }
        }

        [HttpGet("/menu")]
        public async Task<ActionResult<List<MenuItem>>> GetMenu()
        {
            var items = new List<MenuItem>();
            var isAuth = await CasXsrfHandler.IsAuthorized(User?.Identity);
            if (isAuth)
            {
                items.Add(new MenuItem()
                {
                    Name = "Authentication Application",
                    Link = AppLink
                });
                items.Add(new MenuItem()
                {
                    Name = "Other Link",
                    Link = OtherLink
                });
            }
            else
            {
                items.Add(new MenuItem()
                {
                    Name = "Login",
                    Link = LoginLink
                });
            }
            return Ok(items);
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
