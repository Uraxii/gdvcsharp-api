using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Text.RegularExpressions;

namespace GdvCsharp.Controllers
{
    [ApiController]
    [Route("api/{controller}")]
    public class RedosController : ControllerBase
    {
        private const int REGEX_TIMEOUT_MS = 1000;

        [HttpGet("vuln")]
        public IActionResult RedosVuln(string phone)
        {
            string pattern = "^(\\d+)+$";

            Match match = Regex.Match(phone, pattern);

            return Ok(phone + "," + pattern + "," + match.Value + ",");
        }

        [HttpGet("solution")]
        public IActionResult RedosSolution1(string phone)
        {
            // Use a more restrictive regex statement.
            string pattern = "^\\d+7";

            try
            {
                Match match = Regex.Match(
                    phone,
                    pattern,
                    RegexOptions.None,
                    // Like all regex patternts, it's proabbly wrong, so add a restriction to it.
                    // Additonally, this will help gaurd against runnaway expressions.
                    TimeSpan.FromMilliseconds(REGEX_TIMEOUT_MS)
                );

                return Ok(phone + "," + pattern + "," + match.Value + ",");
            }
            catch (RegexMatchTimeoutException ex)
            {
                return BadRequest("Regex evaluation timed out. The pattern is too complex.");
            }
            catch (Exception ex)
            {
                return StatusCode((int)HttpStatusCode.InternalServerError);
            }
        }
    }
}
