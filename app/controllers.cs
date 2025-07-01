using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Text.RegularExpressions;
using System.Net.Http;
using System.Security.Claims;
using System.Text;

namespace GDVCSharp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableController : ControllerBase
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<VulnerableController> _logger;

        // VULNERABILITY: Hard Coded Secrets
        private const string SECRET_API_KEY = "sk-1234567890abcdef";
        private const string DATABASE_PASSWORD = "P@ssw0rd123!";
        private const string JWT_SECRET = "MyVerySecretJWTKey2024!";

        public VulnerableController(ILogger<VulnerableController> logger)
        {
            _logger = logger;
            _httpClient = new HttpClient();
        }

        // VULNERABILITY: Server-Side Request Forgery (SSRF)
        [HttpGet("ssrf")]
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

        // VULNERABILITY: Authorization Bypass
        [HttpPost("admin/users")]
        public IActionResult CreateAdminUser([FromBody] UserRequest request)
        {
            // VULNERABLE: Missing proper authorization check
            // This should require admin role, but doesn't verify it properly

            var userRole = HttpContext.Request.Headers["X-User-Role"].FirstOrDefault();

            // VULNERABLE: Trusting client-supplied header without verification
            if (userRole != "admin")
            {
                // VULNERABLE: Missing return statement - execution continues!
                Unauthorized("Access denied");
            }

            return Ok(new
            {
                message = "Admin user created successfully",
                username = request.Username,
                role = "admin",
                apiKey = SECRET_API_KEY // Exposing secret
            });
        }

        // VULNERABILITY: Regular Expression Denial of Service (ReDoS)
        [HttpGet("validate")]
        public IActionResult ValidateInput(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return BadRequest("Input parameter is required");
            }

            try
            {
                // VULNERABLE: Catastrophic backtracking regex pattern
                var pattern = @"^(a+)+b$";
                var regex = new Regex(pattern);

                // This will hang with input like "aaaaaaaaaaaaaaaaaaaaaac"
                var isValid = regex.IsMatch(input);

                return Ok(new
                {
                    input = input,
                    isValid = isValid,
                    pattern = pattern
                });
            }
            catch (RegexMatchTimeoutException)
            {
                return StatusCode(500, "Regex timeout occurred");
            }
        }

        // VULNERABILITY: Cross-Site Scripting (XSS)
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

        // VULNERABILITY: Path Traversal
        [HttpGet("files")]
        public IActionResult GetFile(string filename)
        {
            if (string.IsNullOrEmpty(filename))
            {
                return BadRequest("Filename parameter is required");
            }

            try
            {
                // VULNERABLE: No path validation - allows directory traversal
                var basePath = Directory.GetCurrentDirectory();
                var filePath = Path.Combine(basePath, "uploads", filename);

                // This allows access to files like "../../../etc/passwd"
                if (System.IO.File.Exists(filePath))
                {
                    var content = System.IO.File.ReadAllText(filePath);
                    return Ok(new
                    {
                        filename = filename,
                        content = content,
                        path = filePath
                    });
                }

                return NotFound($"File '{filename}' not found");
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    error = "Error reading file",
                    details = ex.Message,
                    filename = filename
                });
            }
        }

        // Additional vulnerable endpoint combining multiple issues
        [HttpPost("process")]
        public async Task<IActionResult> ProcessData([FromBody] ProcessRequest request)
        {
            // VULNERABLE: Multiple security issues in one endpoint

            // 1. Hard-coded credentials check
            if (request.ApiKey != SECRET_API_KEY)
            {
                return Unauthorized("Invalid API key");
            }

            // 2. SSRF vulnerability
            if (!string.IsNullOrEmpty(request.CallbackUrl))
            {
                try
                {
                    await _httpClient.PostAsync(request.CallbackUrl,
                        new StringContent($"Processing completed for user: {request.Username}"));
                }
                catch { /* Ignore callback errors */ }
            }

            // 3. XSS in response
            var responseHtml = $@"
                <div>
                    <h3>Processing Result</h3>
                    <p>User: {request.Username}</p>
                    <p>Data: {request.Data}</p>
                    <script>alert('Welcome {request.Username}!');</script>
                </div>";

            return Ok(new
            {
                success = true,
                html = responseHtml,
                processedBy = Environment.UserName,
                secrets = new
                {
                    dbPassword = DATABASE_PASSWORD,
                    jwtSecret = JWT_SECRET
                }
            });
        }

        // Endpoint to demonstrate how secrets are exposed
        [HttpGet("config")]
        public IActionResult GetConfiguration()
        {
            return Ok(new
            {
                database = new
                {
                    server = "localhost",
                    username = "sa",
                    password = DATABASE_PASSWORD // VULNERABLE: Exposing password
                },
                jwt = new
                {
                    secret = JWT_SECRET, // VULNERABLE: Exposing JWT secret
                    expiry = "24h"
                },
                external = new
                {
                    apiKey = SECRET_API_KEY, // VULNERABLE: Exposing API key
                    endpoint = "https://api.external.com"
                }
            });
        }

        // VULNERABILITY: Secrets in GET Request Parameters and URL
        [HttpGet("auth")]
        public IActionResult AuthenticateWithSecrets(string username, string password, string apiKey)
        {
            // VULNERABLE: Secrets passed as GET parameters are logged and cached
            _logger.LogInformation($"Authentication attempt for user: {username} with password: {password} and apiKey: {apiKey}");

            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                return BadRequest("Username and password are required");
            }

            // VULNERABLE: Secrets in GET requests appear in:
            // - Server logs
            // - Browser history
            // - Proxy logs
            // - Referrer headers
            // - Web server access logs

            var isValidCredentials = username == "admin" && password == "secret123";
            var isValidApiKey = apiKey == SECRET_API_KEY;

            if (isValidCredentials && isValidApiKey)
            {
                return Ok(new
                {
                    message = "Authentication successful",
                    token = "jwt-token-here",
                    user = username,
                    // VULNERABLE: Exposing secrets in response
                    usedPassword = password,
                    usedApiKey = apiKey,
                    internalSecret = JWT_SECRET
                });
            }

            return Unauthorized(new
            {
                error = "Invalid credentials",
                // VULNERABLE: Revealing what was attempted
                attemptedUsername = username,
                attemptedPassword = password,
                attemptedApiKey = apiKey
            });
        }

        // VULNERABILITY: Regular Expression Injection
        [HttpGet("regex-search")]
        public IActionResult RegexSearch(string pattern, string text)
        {
            if (string.IsNullOrEmpty(pattern) || string.IsNullOrEmpty(text))
            {
                return BadRequest("Both pattern and text parameters are required");
            }

            try
            {
                // VULNERABLE: User-controlled regex pattern allows injection
                // This can lead to ReDoS, information disclosure, or unexpected behavior
                var regex = new Regex(pattern, RegexOptions.IgnoreCase);
                var matches = regex.Matches(text);

                var results = new List<object>();
                foreach (Match match in matches)
                {
                    results.Add(new
                    {
                        value = match.Value,
                        index = match.Index,
                        length = match.Length,
                        groups = match.Groups.Cast<Group>().Select(g => new
                        {
                            value = g.Value,
                            index = g.Index
                        })
                    });
                }

                return Ok(new
                {
                    pattern = pattern,
                    text = text,
                    matchCount = matches.Count,
                    matches = results,
                    // VULNERABLE: Exposing system information
                    systemInfo = new
                    {
                        machineName = Environment.MachineName,
                        userName = Environment.UserName,
                        osVersion = Environment.OSVersion.ToString()
                    }
                });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new
                {
                    error = "Invalid regex pattern",
                    details = ex.Message,
                    pattern = pattern,
                    // VULNERABLE: Information disclosure through error messages
                    stackTrace = ex.StackTrace
                });
            }
            catch (RegexMatchTimeoutException ex)
            {
                return StatusCode(500, new
                {
                    error = "Regex timeout - possible ReDoS attack",
                    pattern = pattern,
                    details = ex.Message
                });
            }
        }

        // VULNERABILITY: Enhanced Regular Expression Denial of Service (ReDoS)
        [HttpGet("regex-validate")]
        public IActionResult RegexValidate(string input, string customPattern = null)
        {
            if (string.IsNullOrEmpty(input))
            {
                return BadRequest("Input parameter is required");
            }

            try
            {
                string pattern;
                if (!string.IsNullOrEmpty(customPattern))
                {
                    // VULNERABLE: User can provide their own catastrophic regex patterns
                    pattern = customPattern;
                }
                else
                {
                    // VULNERABLE: Multiple catastrophic backtracking patterns
                    var vulnerablePatterns = new[]
                    {
                        @"^(a+)+b$",                    // Classic ReDoS
                        @"^(a|a)*b$",                   // Alternation ReDoS
                        @"^([a-zA-Z]+)*$",              // Character class ReDoS
                        @"^(.*a){10,}$",                // Nested quantifier ReDoS
                        @"^(\w+\s?)*$",                 // Word boundary ReDoS
                        @"^(x+x+)+y$",                  // Exponential ReDoS
                        @"^(([a-z])+.)+[A-Z]([a-z])+$" // Complex nested ReDoS
                    };

                    // Use the first pattern by default
                    pattern = vulnerablePatterns[0];
                }

                var startTime = DateTime.UtcNow;

                // VULNERABLE: No timeout protection
                var regex = new Regex(pattern);
                var isValid = regex.IsMatch(input);

                var endTime = DateTime.UtcNow;
                var processingTime = endTime - startTime;

                return Ok(new
                {
                    input = input,
                    pattern = pattern,
                    isValid = isValid,
                    processingTimeMs = processingTime.TotalMilliseconds,
                    warning = processingTime.TotalSeconds > 1 ? "Slow regex detected - possible ReDoS" : null,
                    // VULNERABLE: Exposing performance metrics can help attackers
                    systemMetrics = new
                    {
                        currentMemory = GC.GetTotalMemory(false),
                        processorCount = Environment.ProcessorCount,
                        workingSet = Environment.WorkingSet
                    }
                });
            }
            catch (RegexMatchTimeoutException ex)
            {
                return StatusCode(500, new
                {
                    error = "Regex timeout occurred",
                    input = input,
                    pattern = customPattern,
                    details = ex.Message,
                    // VULNERABLE: Detailed error information
                    timeout = ex.MatchTimeout,
                    stackTrace = ex.StackTrace
                });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new
                {
                    error = "Invalid regex pattern",
                    pattern = customPattern,
                    details = ex.Message,
                    input = input
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    error = "Unexpected error during regex processing",
                    type = ex.GetType().Name,
                    message = ex.Message,
                    // VULNERABLE: Full exception details exposed
                    stackTrace = ex.StackTrace,
                    innerException = ex.InnerException?.Message
                });
            }
        }

        // VULNERABILITY: Combined endpoint with multiple ReDoS patterns
        [HttpGet("multi-regex")]
        public IActionResult MultiRegexValidation(string email, string phone, string ssn)
        {
            var results = new List<object>();
            var startTime = DateTime.UtcNow;

            try
            {
                if (!string.IsNullOrEmpty(email))
                {
                    // VULNERABLE: Complex email regex prone to ReDoS
                    var emailPattern = @"^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$";
                    var emailRegex = new Regex(emailPattern);
                    results.Add(new
                    {
                        field = "email",
                        value = email,
                        isValid = emailRegex.IsMatch(email),
                        pattern = emailPattern
                    });
                }

                if (!string.IsNullOrEmpty(phone))
                {
                    // VULNERABLE: Phone regex with catastrophic backtracking
                    var phonePattern = @"^(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$";
                    var phoneRegex = new Regex(phonePattern);
                    results.Add(new
                    {
                        field = "phone",
                        value = phone,
                        isValid = phoneRegex.IsMatch(phone),
                        pattern = phonePattern
                    });
                }

                if (!string.IsNullOrEmpty(ssn))
                {
                    // VULNERABLE: SSN regex susceptible to ReDoS
                    var ssnPattern = @"^(?!666|000|9\\d{2})\\d{3}-?(?!00)\\d{2}-?(?!0{4})\\d{4}$";
                    var ssnRegex = new Regex(ssnPattern);
                    results.Add(new
                    {
                        field = "ssn",
                        value = ssn,
                        isValid = ssnRegex.IsMatch(ssn),
                        pattern = ssnPattern
                    });
                }

                var endTime = DateTime.UtcNow;
                var totalTime = endTime - startTime;

                return Ok(new
                {
                    results = results,
                    processingTimeMs = totalTime.TotalMilliseconds,
                    timestamp = endTime,
                    // VULNERABLE: Exposing detailed system information
                    systemInfo = new
                    {
                        machineName = Environment.MachineName,
                        osVersion = Environment.OSVersion,
                        clrVersion = Environment.Version,
                        memoryUsage = GC.GetTotalMemory(false),
                        uptime = Environment.TickCount
                    }
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    error = "Multi-regex validation failed",
                    details = ex.Message,
                    // VULNERABLE: Complete exception exposure
                    exception = new
                    {
                        type = ex.GetType().FullName,
                        message = ex.Message,
                        stackTrace = ex.StackTrace,
                        source = ex.Source,
                        targetSite = ex.TargetSite?.ToString()
                    }
                });
            }
        }
    }

    // Supporting classes
    public class UserRequest
    {
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
    }

    public class ProcessRequest
    {
        public string Username { get; set; } = string.Empty;
        public string Data { get; set; } = string.Empty;
        public string ApiKey { get; set; } = string.Empty;
        public string CallbackUrl { get; set; } = string.Empty;
    }
}
