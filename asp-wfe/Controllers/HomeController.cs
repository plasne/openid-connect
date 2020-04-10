using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using asp_wfe.Models;
using Microsoft.AspNetCore.Authorization;
using CasAuth;
using System.Threading.Tasks;

namespace asp_wfe.Controllers
{

    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly ICasConfig _config;

        public HomeController(ILogger<HomeController> logger, ICasConfig config)
        {
            _logger = logger;
            _config = config;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Redirector()
        {
            return View();
        }

        public async Task<IActionResult> Login()
        {
            if (User.Identity.IsAuthenticated)
            {
                return View();
            }
            else
            {
                var loginUrl = await _config.GetString("LOGIN_URL") ?? "http://localhost:5100/cas/authorize";
                var redirectUrl = await _config.GetString("REDIRECT_URL") ?? "http://localhost:5000/Home/Redirector";
                var uri = System.Web.HttpUtility.UrlEncode(redirectUrl);
                return Redirect($"{loginUrl}?redirecturi={uri}");
            }
        }

        [Authorize("cas-no-xsrf")]
        public IActionResult AuthN()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

    }
}
