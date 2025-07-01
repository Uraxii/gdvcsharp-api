using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;

namespace GDVCSharp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class RegexController : ControllerBase
    {
        private readonly ILogger<RegexController> _logger;

        public RegexController(ILogger<RegexController> logger)
        {
            _logger = logger;
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

        // VULNERABILITY: Regular Expression Injection
        [HttpGet("search")]
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
        [HttpGet("validate-enhanced")]
        public IActionResult RegexValidateEnhanced(string input, string customPattern = null)
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
        [HttpGet("multi-validate")]
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
}
