using System;
using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
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

        private readonly IConfiguration _config;
        private readonly UserService _userService;

        public AuthBypassController(IConfiguration config, UserService userService)
        {
            _userService = userService;
            _config = config;
        }

        [HttpPost("vuln")]
        public IActionResult vuln([FromBody] LoginUser model)
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

            if (!user.Roles.Contains("admin"))
            {
                Unauthorized("Invalid permissions");
            }

            return Ok("Heres the Dashboard");
        }

        [HttpPost("solution")]
        public IActionResult solution([FromBody] LoginUser model)
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

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtSettings:Key"]!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username)
            };

            claims.AddRange(user.Roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            
            var token = tokenHandler.CreateToken(tokenDescriptor);

            string jwt = tokenHandler.WriteToken(token);

            var jwtToken = tokenHandler.ReadJwtToken(jwt);

            return Ok(new { token = jwt});

        }

        [HttpGet("viewDashboard")]
        [Authorize(Roles="admin")]
        public IActionResult viewDashboard()
        {
            return Ok("Heres the Dashboard");
        }

    }
}
