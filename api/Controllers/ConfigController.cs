using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Text.RegularExpressions;
using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ConfigController : ControllerBase
    {

        private class BadRequestException : Exception
        {
            public BadRequestException(string message) : base(message) { }
        }

        private class NotFoundException : Exception
        {
            public NotFoundException(string message) : base(message) { }
        }

        [AllowAnonymous]
        [HttpGet, Route("{name}")]
        public async Task<ActionResult<Dictionary<string, string>>> GetConfigByName(string name)
        {
            try
            {

                // validate the name is alpha numeric only
                Console.WriteLine("name: " + name);
                if (!name.All(char.IsLetterOrDigit)) throw new BadRequestException("invalid name");

                // look for env that would allow this config
                string compact = System.Environment.GetEnvironmentVariable($"PRESENT_CONFIG_{name.ToUpper()}");
                var filters = Config.ParseFilterString(compact);
                if (filters.Length < 1) throw new NotFoundException("filter not found");

                // return the config
                return await Config.Load(filters);

            }
            catch (BadRequestException e)
            {
                return BadRequest(e.Message);
            }
            catch (NotFoundException e)
            {
                return NotFound(e.Message);
            }
        }

    }

}
