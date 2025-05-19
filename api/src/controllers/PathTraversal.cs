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

            string baseDir = "static/files/nutrition";

            string path = Path.Combine(Directory.GetCurrentDirectory(), baseDir, filename);

            if (!System.IO.File.Exists(path))
            {
                return NotFound("File not found.");
            }

            try
            {
                string contents = System.IO.File.ReadAllText(path);

                return Content(contents, "text/plain");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error reading file: {ex.Message}");
            }
        }

        [HttpGet("solution")]
        public IActionResult PathTraversalSolution(string filename)
        {
            if (string.IsNullOrWhiteSpace(filename) || filename.Contains(".."))
            {
                return BadRequest("Invalid Filename.");
            }

            string baseDir = "static/files/nutrition";

            //If filename is an absolute path, current directory and baseUrl won't be included
            string path = Path.Combine(Directory.GetCurrentDirectory(), baseDir, filename);

            string absPath = Path.GetFullPath(path);

            string basePath = Path.Combine(Directory.GetCurrentDirectory(), baseDir);

            //Check that the file path starts with the intended base directory
            if (!absPath.StartsWith(basePath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                return BadRequest("Access Denied: Invalid Path.");
            }
            if (!System.IO.File.Exists(absPath))
            {
                return NotFound("File not found.");
            }

            try
            {
                string contents = System.IO.File.ReadAllText(absPath);

                return Content(contents, "text/plain");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error reading file: {ex.Message}");
            }
        }
    }
}