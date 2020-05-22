using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using asp_wfe.Models;
using Microsoft.AspNetCore.Authorization;
using CasAuth;
using System.Threading.Tasks;
using System.Net.Http;
using System;
using NetBricks;

namespace asp_wfe.Controllers
{

    public class HomeController : Controller
    {

        public HomeController(
            ILogger<HomeController> logger,
            IHttpClientFactory httpClientFactory
        )
        {
            Logger = logger;
            HttpClient = httpClientFactory.CreateClient("wfe");
        }

        private ILogger<HomeController> Logger { get; }
        private HttpClient HttpClient { get; }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Redirector()
        {
            return View();
        }

        public class UserInfo
        {
            public string email { get; set; }
            public string name { get; set; }
            public string oid { get; set; }
        }

        public async Task<IActionResult> Login()
        {
            if (User.Identity.IsAuthenticated)
            {

                // get the full list of cookies to pass on
                //  NOTE: we actually only need the "user" cookie, but maybe your API has need of other cookies
                string cookie = Request.Headers["Cookie"];

                // get the XSRF-TOKEN cookie so we can make it into a header
                string xsrf = Request.Cookies["XSRF-TOKEN"];

                // if authenticated, make a call to another API
                UserInfo userinfo = null;
                var meUrl = Config.GetOnce("ME_URL") ?? "http://localhost:5200/cas/me";
                using (var req = new HttpRequestMessage()
                {
                    RequestUri = new Uri(meUrl),
                    Method = HttpMethod.Get
                })
                {
                    req.Headers.Add("Cookie", cookie);
                    req.Headers.Add("X-XSRF-TOKEN", xsrf);
                    using (var response = await HttpClient.SendAsync(req))
                    {
                        var raw = await response.Content.ReadAsStringAsync();
                        if (!response.IsSuccessStatusCode)
                        {
                            Console.WriteLine($"Login: HTTP {(int)response.StatusCode} - {raw}");
                        }
                        userinfo = System.Text.Json.JsonSerializer.Deserialize<UserInfo>(raw);
                        Console.WriteLine(raw);
                        Console.WriteLine($"email: {userinfo.email}");
                    }
                };

                // return the view with our UserInfo as the Model
                return View(userinfo);

            }
            else
            {
                var loginUrl = Config.GetOnce("LOGIN_URL") ?? "http://localhost:5100/cas/authorize";
                var redirectUrl = Config.GetOnce("REDIRECT_URL") ?? "http://localhost:5000/Home/Redirector";
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
