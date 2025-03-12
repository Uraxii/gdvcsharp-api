using Microsoft.AspNetCore.Mvc;
using GdvCsharp.API.Models;
using GdvCsharp.API.Services;

namespace GdvCsharp.API.Controllers
{
    [ApiController]
    [Route("api/{controller}")]
    public class UserController : ControllerBase
    {
        private readonly UserService _userService;

        public UserController(UserService userService)
        {
            _userService = userService;
        }

        // This is bad. Never do this :D
        [HttpGet]
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

        // No AuthN or AuthZ implemented. This is bad!
        [HttpGet("{userId}")]
        public IActionResult UserInfo(string userId)
        {
            var user = _userService.GetUserFromId(userId);

            if (user == null)
            {
                return Unauthorized("Not authorized.");
            }

            return Ok(user);
        }

        // No AuthN or AuthZ implemented. This is bad!
        [HttpDelete("{userId}")]
        public IActionResult UnregisterUser(string userId)
        {
            if (!_userService.DeleteUser(userId).Result)
            {
                return BadRequest("Unable to delete user.");
            }

            return Ok("User deleted.");
        }


        private bool IsLocalRequest()
        {
            var connection = HttpContext.Connection;
            var remoteIp = connection.RemoteIpAddress?.ToString();

            return remoteIp == "127.0.0.1" || remoteIp == "::1";
        }
    }
}
