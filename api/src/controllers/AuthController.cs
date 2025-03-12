using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using GdvCsharp.API.Models;
using GdvCsharp.API.Services;

namespace GdvCsharp.API.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly UserService _userService;

        public AuthController(UserService userService)
        {
            _userService = userService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUserAsync([FromBody] RegisterUser model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (_userService.GetUserFromEmail(model.Email) != null)
            {
                return BadRequest("Account with that email already exists.");
            }

            if (_userService.GetUser(model.Username) != null)
            {
                return BadRequest("Account with that username alreadt exists.");
            }

            var user = await _userService.CreateUserAsync(model.Email, model.Username, model.Password);

            return Ok("User registered.");
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginUser model)
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

            return Ok("Login successful.");
        }

    }
}
