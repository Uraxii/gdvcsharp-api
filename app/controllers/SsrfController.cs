using Microsoft.AspNetCore.Mvc;

namespace GDVCSharp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SsrfController : ControllerBase
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<SsrfController> _logger;

        public SsrfController(ILogger<SsrfController> logger)
        {
            _logger = logger;
            _httpClient = new HttpClient();
        }

        // VULNERABILITY: Server-Side Request Forgery (SSRF)
        [HttpGet("vulnerable")]
        public async Task<IActionResult> ServerSideRequestForgery(string url)
        {
            try
            {
                if (string.IsNullOrEmpty(url))
                {
                    return BadRequest("URL parameter is required");
                }

                // VULNERABLE: No validation of the URL - allows internal network access
                var response = await _httpClient.GetStringAsync(url);

                return Ok(new
                {
                    message = "Request successful",
                    data = response,
                    requestedUrl = url
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new
                {
                    error = "Failed to fetch URL",
                    details = ex.Message,
                    requestedUrl = url
                });
            }
        }

        // VULNERABILITY: SSRF with POST method
        [HttpPost("post-vulnerable")]
        public async Task<IActionResult> PostSsrfVulnerable([FromBody] SsrfRequest request)
        {
            try
            {
                if (string.IsNullOrEmpty(request.Url))
                {
                    return BadRequest("URL is required");
                }

                var content = new StringContent(request.Data ?? "", System.Text.Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync(request.Url, content);
                var responseContent = await response.Content.ReadAsStringAsync();

                return Ok(new
                {
                    message = "POST request successful",
                    statusCode = (int)response.StatusCode,
                    data = responseContent,
                    requestedUrl = request.Url,
                    sentData = request.Data
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new
                {
                    error = "Failed to POST to URL",
                    details = ex.Message,
                    requestedUrl = request.Url
                });
            }
        }
    }

    public class SsrfRequest
    {
        public string Url { get; set; } = string.Empty;
        public string Data { get; set; } = string.Empty;
    }
}
