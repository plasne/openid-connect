# ASPNET.CORE MVP Sample (LEGACY)

I do NOT believe there is any case by which you should design a new website using this method. You should develop all of your business logic in one or more APIs and you should develop your WFE using client-side web technologies like HTML/CSS/Javascript, Angular, React, etc.

However, it was mentioned to me recently that people might already have code written in ASPNET.CORE with Razor pages and the like and might need some assistance in getting this sample to work.

For greenfield development you should typically:

-   Deploy the Auth Server service
-   Deploy one or more API Client services
-   Deploy one or more WFE services - typically just HTML, CSS, and JS hosted via NGINX or similar

## Deployment

I started by running...

```bash
dotnet new mvc
```

Then I modified the Startup.cs...

```c#
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{

    // log settings
    var config = app.ApplicationServices.GetService<ICasConfig>();
    config.Optional("LOGIN_URL");
    config.Optional("REDIRECT_URL");

    // HSTS, HTTPS, dev-error-pages, etc...

    // establish the pipeline
    app.UseStaticFiles();
    app.UseRouting();
    app.UseAuthentication();  // <-- added auth to all pages
    app.UseAuthorization();
    app.UseCasClientAuth();   // <-- added CasAuth
    app.UseEndpoints(endpoints =>
    {
        endpoints.MapControllerRoute(
            name: "default",
            pattern: "{controller=Home}/{action=Index}/{id?}");
    });

}
```

Of course, you could be more discriminatory in what you applied Authentication too.

In HomeController.cs, I modified it like so...

```c#
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
```

Notice that the AuthN endpoint (the page that needs authentication) is suppressing the XSRF check (this uses a new feature in 2.5.0+). The reason for that is aspnetcore doesn't send a XSRF header when you browse to a page, nor does it probably need to. Best practice is that GET requests should never alter the state of anything so XSRF isn't needed. While I generally do check for XSRF on every request using CasAuth, there is no good way to address that for aspnetcore, so you can leave it off.

Beyond that, aspnetcore does offer XSRF protection for POST and similar endpoints natively. So you could always suppress CasAuth XSRF protection and simply use this: https://docs.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-3.1.

What I would generally recommend is that your WFE and your APIs be separate deployed solutions anyway, and then you can suppress XSRF for aspnetcore pages but leave it intact for your entire API surface.

I created each of those pages (Redirector, Login, and AuthN). The Redirector page needs the following on the page...

```javascript
<script>window.location.href="http://localhost:5000/Home/Login";</script>
```

The /token endpoint returns the cookies necessary for authentication via a 302 redirect. Normally if that just lands on a HTML page that uses AJAX to consume API services, that isn't an issue, but if we want to check for authentication in aspnetcore, unfortunately, it doesn't look like most browsers are passing those cookies when the first page is redirected. The workaround is use Javascript to redirect that one last time instead of using a 302.

## Configuration

Because aspnetcore runs server-side, you can use App Config for configuration natively, though this is certainly not a requirement if you already are managing configuration another way.

Adding the Optional() or Required() variables to the Startup allows you to see what configuration came in when running LOG_LEVEL=Debug.

```
dbug: CasAuth.CasConfig[0]
      LOGIN_URL = "http://localhost:5100/cas/authorize"
dbug: CasAuth.CasConfig[0]
      REDIRECT_URL = "http://localhost:5000/Home/Redirector"
```

## Authenticate Everything

I had a customer that needed to authenticate everything, even static assets. To do that, you can move the authentication above UseStaticFiles() and then add middleware to redirect if not going to the Redirector or already authenticated.

```c#
// route and authenticate
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

// redirect if not authenticated
app.UseWhen(context =>
{
    if (context.User.Identity.IsAuthenticated) return false;
    if (context.Request.Path.Value.EndsWith("/Home/Redirector")) return false;
    return true;
}, app =>
{
    app.Run(async context =>
    {
        var loginUrl = await config.GetString("LOGIN_URL") ?? "http://localhost:5100/cas/authorize";
        var redirectUrl = await config.GetString("REDIRECT_URL") ?? "http://localhost:5000/Home/Redirector";
        var uri = System.Web.HttpUtility.UrlEncode(redirectUrl);
        context.Response.Redirect($"{loginUrl}?redirecturi={uri}");
    });
});

// present static files and so on...
app.UseStaticFiles();
app.UseCasClientAuth();
app.UseEndpoints(endpoints =>
{
    endpoints.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}");
});
```

## Calling External Services from ASPNETCORE Backend

To further enhance the sample, I added a call to an external API service. In this case, I am running a CasAuth API service, which has a /cas/me endpoint that requires authentication. I just need to collect the session token ("user" cookie by default) and the XSRF-TOKEN cookie so that I can properly pass those as headers. Then it is just a normal HTTP call.

```c#
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
        var meUrl = await _config.GetString("ME_URL") ?? "http://localhost:5200/cas/me";
        using (var req = new HttpRequestMessage()
        {
            RequestUri = new Uri(meUrl),
            Method = HttpMethod.Get
        })
        {
            req.Headers.Add("Cookie", cookie);
            req.Headers.Add("X-XSRF-TOKEN", xsrf);
            using (var response = await _httpClient.SendAsync(req))
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
        var loginUrl = await _config.GetString("LOGIN_URL") ?? "http://localhost:5100/cas/authorize";
        var redirectUrl = await _config.GetString("REDIRECT_URL") ?? "http://localhost:5000/Home/Redirector";
        var uri = System.Web.HttpUtility.UrlEncode(redirectUrl);
        return Redirect($"{loginUrl}?redirecturi={uri}");
    }
}
```
