using Microsoft.AspNetCore.Mvc;

namespace GdvCsharp.API.Controllers
{
    [ApiController]
    [Route("api/{controller}")]
    public class PathTraversalController : ControllerBase
    {
        [HttpGet("vuln")]
        public IActionResult PathTraversalVuln(string filename)
        {

            if (string.IsNullOrWhiteSpace(filename) || filename.Contains(".."))
            {
                return BadRequest("Invalid Filename.");
            }

            string baseUrl = "static/files/nutrition";

            string fullPath = Path.Combine(Directory.GetCurrentDirectory(), baseUrl, filename);

            if (!System.IO.File.Exists(fullPath))
            {
                return NotFound("File not found.");
            }

            try
            {
                string contents = System.IO.File.ReadAllText(fullPath);

                return Content(contents, "text/plain");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error reading file: {ex.Message} in {fullPath} {Directory.GetCurrentDirectory()}");
            }
        }

        [HttpGet("solution")]
        public IActionResult PathTraversalSolution(string filename)
        {
            if (string.IsNullOrWhiteSpace(filename) || filename.Contains(".."))
            {
                return BadRequest("Invalid Filename.");
            }

            string baseUrl = "static/files/nutrition";

            //If filename is an absolute path, current directory and baseUrl won't be included
            string fullPath = Path.Combine(Directory.GetCurrentDirectory(), baseUrl, filename);

            string baseDir = Path.Combine(Directory.GetCurrentDirectory(), baseUrl);

            //Check that the file path starts with the intended base directory
            if (!fullPath.StartsWith(baseDir))
            {
                return BadRequest("Access Denied: Invalid Path.");
            }

            if (!System.IO.File.Exists(fullPath))
            {
                return NotFound("File not found.");
            }

            try
            {
                string contents = System.IO.File.ReadAllText(fullPath);

                return Content(contents, "text/plain");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error reading file: {ex.Message}");
            }
        }
    }
}