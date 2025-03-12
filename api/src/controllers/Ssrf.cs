using GdvCsharp.API.Models;
using GdvCsharp.API.Services;
using Microsoft.AspNetCore.Mvc;

namespace GdvCsharp.API.Controllers
{
    [ApiController]
    [Route("api/{controller}")]
    public class SsrfController : ControllerBase
    {
        private readonly HttpClient _httpClient;
        private readonly UserService _userService;

        public SsrfController(UserService userService)
        {
            _httpClient = new HttpClient();
            _userService = userService;
        }

        [HttpGet("vuln")]
        public async Task<IActionResult> GetDataVulnAsync(string uri)
        {
            if (uri == "")
            {
                return BadRequest("uri parameter null!");
            }

            try
            {
                var response = await _httpClient.GetStringAsync(uri);

                return Content(response, "text/plain");
            }
            catch (Exception ex)
            {
                return BadRequest($"Error fetching data from {uri}.");
            }
        }

        [HttpGet("solution")]
        public async Task<IActionResult> SsrfSolutionAsync(string uri)
        {
            if (uri == "")
            {
                return BadRequest("uri parameter null!");
            }

            // Check if user is request local resources. If so, deny the request.
            // There is WAY better solution to this! Implement it here!!!!
            if (uri.Contains("localhost"))
            {
                return BadRequest("Invalid URI.");
            }

            try
            {
                var response = await _httpClient.GetStringAsync(uri);

                return Content(response, "text/plain");
            }
            catch (Exception ex)
            {
                return BadRequest($"Error fetching data from {uri}.");
            }
        }

        // This is bad. Never do this :D
        // AuthN / AuthZ
        [HttpGet("users")]
        public IActionResult GetAllUsers()
        {
            if (!IsLocalRequest())
            {
                return Unauthorized("Not permitted.");
            }

            List<User> users = _userService.GetAllUsers();

            return Ok(users); // Returns full user data, including sensitive fields

            // string connectionString = Environment.GetEnvironmentVariable("MONGO_CONNECTION_STRING");

            // return Ok(connectionString);
        }

        private bool IsLocalRequest()
        {
            var connection = HttpContext.Connection;
            var remoteIp = connection.RemoteIpAddress?.ToString();

            return remoteIp == "127.0.0.1" || remoteIp == "::1";
        }
    }


}
