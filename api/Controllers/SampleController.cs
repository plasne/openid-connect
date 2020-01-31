using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using CasAuth;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace authentication.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class SampleController : ControllerBase
    {

        public SampleController(IHttpClientFactory httpClientFactory)
        {
            this.HttpClient = httpClientFactory.CreateClient("api");
        }

        private HttpClient HttpClient { get; }

        [AllowAnonymous]
        [HttpGet, Route("version")]
        public ActionResult<string> Version()
        {
            return "v2.0.0";
        }

        [Authorize]
        [HttpGet, Route("propogate")]
        public async Task<ActionResult<string>> Propogate()
        {
            // sample showing connecting to a downstream service
            using (var request = new HttpRequestMessage()
            {
                RequestUri = new Uri($"http://localhost:5300/sample/name"),
                Method = HttpMethod.Get
            })
            {
                using (var response = await this.HttpClient.SendAsync(request))
                {
                    var raw = await response.Content.ReadAsStringAsync();
                    if (!response.IsSuccessStatusCode)
                    {
                        throw new Exception($"exception: HTTP {(int)response.StatusCode} - {raw}");
                    }
                    return Ok(raw);
                }
            };
        }

    }

}
