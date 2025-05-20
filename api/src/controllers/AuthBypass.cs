using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using GdvCsharp.API.Models;
using GdvCsharp.API.Services;

namespace GdvCsharp.API.Controllers
{
    [ApiController]
    [Route("api/authbypass")]
    public class AuthBypassController : ControllerBase
    {
        private readonly UserService _userService;

        public AuthBypassController(UserService userService)
        {
            _userService = userService;
        }

        [HttpPost("viewDashboard")]
        public IActionResult viewDashboard([FromBody] LoginUser model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = _userService.AuthenticateUser(model.Username, model.Password);

            if (user == null) // No password hashing, salt, encryption, etc. (OWASP A07:2021)
            {
                return Unauthorized("Invalid credentials.");
            }

            if (user.IsAdmin)
            {
                return Ok("Here's the dashboard");
            }
            else
            {
                return BadRequest("Invalid permissions");
            }
        }

    }
}
