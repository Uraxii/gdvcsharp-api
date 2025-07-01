using Microsoft.AspNetCore.Mvc;

namespace GDVCSharp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class XssController : ControllerBase
    {
        private readonly ILogger<XssController> _logger;

        public XssController(ILogger<XssController> logger)
        {
            _logger = logger;
        }

        // VULNERABILITY: Cross-Site Scripting (XSS) - Reflected
        [HttpGet("search")]
        public IActionResult Search(string query)
        {
            if (string.IsNullOrEmpty(query))
            {
                return BadRequest("Query parameter is required");
            }

            // VULNERABLE: Reflecting user input without encoding
            var htmlResponse = $@"
                <html>
                <head><title>Search Results</title></head>
                <body>
                    <h1>Search Results</h1>
                    <p>You searched for: {query}</p>
                    <div id='results'>
                        <p>No results found for '{query}'</p>
                    </div>
                    <script>
                        console.log('Search query: {query}');
                    </script>
                </body>
                </html>";

            return Content(htmlResponse, "text/html");
        }

        // VULNERABILITY: XSS in JSON response
        [HttpGet("profile")]
        public IActionResult GetProfile(string username, string bio)
        {
            if (string.IsNullOrEmpty(username))
            {
                return BadRequest("Username parameter is required");
            }

            // VULNERABLE: XSS in JSON response that gets rendered client-side
            return Ok(new
            {
                success = true,
                profile = new
                {
                    username = username,
                    bio = bio ?? "No bio available",
                    // VULNERABLE: HTML content without encoding
                    welcomeMessage = $"<h2>Welcome back, {username}!</h2>",
                    profileHtml = $@"
                        <div class='profile-card'>
                            <h3>{username}</h3>
                            <p>{bio}</p>
                            <script>console.log('User: {username}');</script>
                        </div>"
                },
                timestamp = DateTime.UtcNow
            });
        }

        // VULNERABILITY: XSS via HTTP headers
        [HttpGet("feedback")]
        public IActionResult SubmitFeedback(string message, string category = "general")
        {
            if (string.IsNullOrEmpty(message))
            {
                return BadRequest("Message parameter is required");
            }

            // VULNERABLE: Reflecting user input in response
            var feedbackId = Guid.NewGuid().ToString();

            var htmlResponse = $@"
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Feedback Submitted</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 40px; }}
                        .feedback {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
                        .category {{ color: #666; }}
                    </style>
                </head>
                <body>
                    <h1>Thank You for Your Feedback!</h1>
                    <div class='feedback'>
                        <p><strong>Feedback ID:</strong> {feedbackId}</p>
                        <p><strong>Category:</strong> <span class='category'>{category}</span></p>
                        <p><strong>Your Message:</strong></p>
                        <blockquote>{message}</blockquote>
                    </div>
                    <script>
                        // VULNERABLE: User input directly in JavaScript
                        var feedbackData = {{
                            id: '{feedbackId}',
                            category: '{category}',
                            message: '{message}',
                            timestamp: '{DateTime.UtcNow}'
                        }};
                        console.log('Feedback submitted:', feedbackData);
                    </script>
                </body>
                </html>";

            return Content(htmlResponse, "text/html");
        }

        // VULNERABILITY: DOM-based XSS setup
        [HttpGet("dashboard")]
        public IActionResult Dashboard(string theme = "light")
        {
            // VULNERABLE: Creating client-side XSS opportunity
            var htmlResponse = $@"
                <!DOCTYPE html>
                <html>
                <head>
                    <title>User Dashboard</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; }}
                        .{theme} {{ background: {(theme == "dark" ? "#333" : "#fff")}; color: {(theme == "dark" ? "#fff" : "#333")}; }}
                    </style>
                </head>
                <body class='{theme}'>
                    <h1>Dashboard</h1>
                    <div id='welcome'></div>
                    <div id='theme-info'>Current theme: {theme}</div>
                    
                    <script>
                        // VULNERABLE: DOM manipulation with user input
                        var urlParams = new URLSearchParams(window.location.search);
                        var welcomeMsg = urlParams.get('welcome') || 'Welcome to your dashboard!';
                        document.getElementById('welcome').innerHTML = welcomeMsg;
                        
                        // VULNERABLE: Theme parameter reflected in JavaScript
                        var currentTheme = '{theme}';
                        console.log('Theme loaded: ' + currentTheme);
                        
                        // VULNERABLE: Processing URL fragment
                        if (window.location.hash) {{
                            var hashContent = window.location.hash.substring(1);
                            document.getElementById('welcome').innerHTML += '<br>Hash content: ' + hashContent;
                        }}
                    </script>
                </body>
                </html>";

            return Content(htmlResponse, "text/html");
        }

        // VULNERABILITY: XSS in error messages
        [HttpPost("comment")]
        public IActionResult PostComment([FromBody] CommentRequest request)
        {
            if (request == null || string.IsNullOrEmpty(request.Content))
            {
                return BadRequest("Comment content is required");
            }

            // VULNERABLE: Simulating XSS in error handling
            if (request.Content.Length > 1000)
            {
                var errorHtml = $@"
                    <div style='color: red; border: 1px solid red; padding: 10px;'>
                        <h3>Error: Comment too long</h3>
                        <p>Your comment was {request.Content.Length} characters, but the limit is 1000.</p>
                        <p>Comment preview: {request.Content.Substring(0, Math.Min(200, request.Content.Length))}...</p>
                        <p>Author: {request.Author ?? "Anonymous"}</p>
                    </div>";

                return BadRequest(new { error = "Comment too long", html = errorHtml });
            }

            // VULNERABLE: Storing and reflecting comment without sanitization
            return Ok(new
            {
                success = true,
                comment = new
                {
                    id = Guid.NewGuid(),
                    author = request.Author ?? "Anonymous",
                    content = request.Content,
                    // VULNERABLE: HTML rendering of user content
                    renderedHtml = $@"
                        <div class='comment'>
                            <strong>{request.Author ?? "Anonymous"}</strong> says:
                            <p>{request.Content}</p>
                            <small>Posted at {DateTime.UtcNow}</small>
                        </div>",
                    timestamp = DateTime.UtcNow
                }
            });
        }
    }

    public class CommentRequest
    {
        public string Content { get; set; } = string.Empty;
        public string Author { get; set; } = string.Empty;
    }
}
