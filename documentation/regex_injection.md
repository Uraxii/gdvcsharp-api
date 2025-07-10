# Regular Expression Injection - Deep Dive

## What is Regular Expression Injection?

Regular Expression Injection occurs when user-supplied input is used to construct regular expression patterns without proper validation or sanitization. This vulnerability can lead to Regular Expression Denial of Service (ReDoS), information disclosure, bypassing input validation, or unexpected application behavior.

## Root Cause Analysis

### Understanding the Vulnerability

The core issue arises when applications allow users to control regex patterns:

1. **Direct Pattern Injection**: User input becomes the regex pattern
2. **Pattern Concatenation**: User input is concatenated into existing patterns
3. **Dynamic Pattern Building**: User input influences pattern construction
4. **Unescaped Metacharacters**: Special regex characters not properly escaped

### Dangerous Regex Metacharacters

```
.    - Matches any character
*    - Zero or more of preceding
+    - One or more of preceding
?    - Zero or one of preceding
^    - Start of string
$    - End of string
|    - Alternation (OR)
[]   - Character class
()   - Grouping
{}   - Quantifiers
\    - Escape character
```

### Vulnerable Code Patterns

#### 1. Direct User Pattern Input

```csharp
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
```

**Critical Problems:**
- User completely controls the regex pattern
- No validation or sanitization of pattern
- Detailed error messages reveal system information
- No timeout protection against ReDoS

#### 2. Pattern Concatenation

```csharp
[HttpGet("validate-email")]
public IActionResult ValidateEmailWithDomain(string email, string domainPattern = @"\w+\.com")
{
    try
    {
        // VULNERABLE: User input concatenated into regex pattern
        var fullPattern = $@"^[a-zA-Z0-9._%+-]+@{domainPattern}$";
        var regex = new Regex(fullPattern);
        
        var isValid = regex.IsMatch(email);
        
        return Ok(new
        {
            email = email,
            domainPattern = domainPattern,
            fullPattern = fullPattern, // VULNERABLE: Exposing constructed pattern
            isValid = isValid
        });
    }
    catch (Exception ex)
    {
        return BadRequest(new
        {
            error = "Pattern validation failed",
            domainPattern = domainPattern,
            constructedPattern = $@"^[a-zA-Z0-9._%+-]+@{domainPattern}$",
            details = ex.Message
        });
    }
}
```

**Problems:**
- User input directly concatenated without escaping
- Constructed pattern exposed in response
- No validation of user-supplied pattern fragment

#### 3. Dynamic Search Functionality

```csharp
[HttpGet("log-search")]
public IActionResult SearchLogs(string searchTerm, bool caseSensitive = false, bool useRegex = false)
{
    try
    {
        var logEntries = GetLogEntries(); // Simulated log data
        var results = new List<string>();

        if (useRegex)
        {
            // VULNERABLE: User controls regex pattern for log searching
            var regexOptions = caseSensitive ? RegexOptions.None : RegexOptions.IgnoreCase;
            var regex = new Regex(searchTerm, regexOptions);
            
            results = logEntries.Where(log => regex.IsMatch(log)).ToList();
        }
        else
        {
            // Simple string search
            var comparison = caseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
            results = logEntries.Where(log => log.Contains(searchTerm, comparison)).ToList();
        }

        return Ok(new
        {
            searchTerm = searchTerm,
            useRegex = useRegex,
            caseSensitive = caseSensitive,
            matchCount = results.Count,
            matches = results,
            // VULNERABLE: Potentially exposing sensitive log data
            warning = "This endpoint can expose sensitive information through regex injection"
        });
    }
    catch (ArgumentException ex)
    {
        return BadRequest(new
        {
            error = "Invalid search pattern",
            searchTerm = searchTerm,
            details = ex.Message
        });
    }
}

private List<string> GetLogEntries()
{
    return new List<string>
    {
        "2025-07-01 10:30:45 INFO User john logged in",
        "2025-07-01 10:31:12 ERROR Database connection failed: password=secret123",
        "2025-07-01 10:32:05 INFO API key used: sk-1234567890abcdef",
        "2025-07-01 10:33:18 DEBUG Internal token: jwt-secret-key-2024",
        "2025-07-01 10:34:22 WARN Failed login attempt from 192.168.1.100"
    };
}
```

## How Regex Injection Attacks Work

### Attack Vectors

#### 1. ReDoS via Malicious Patterns
```bash
# Catastrophic backtracking pattern
curl "http://localhost:5000/api/regex/search?pattern=%5E%28a%2B%29%2Bb%24&text=aaaaaaaaaaaaaaaaaac"
# URL decoded: ^(a+)+b$

# Nested quantifier ReDoS
curl "http://localhost:5000/api/regex/search?pattern=%5E%28a%2A%29%2A%24&text=aaaaaaaaaaaaaaaaaab"
# URL decoded: ^(a*)*$
```

**Attack Result:**
- Server CPU usage spikes to 100%
- Request hangs for extended periods
- Application becomes unresponsive
- Potential denial of service

#### 2. Information Disclosure through Pattern Matching
```bash
# Extract sensitive information using regex groups
curl "http://localhost:5000/api/regex/search?pattern=password%3D%28%5B%5E%5Cs%5D%2B%29&text=config%3A%20password%3Dsecret123%20debug%3Dtrue"
# URL decoded: password=([^\s]+)

# Extract API keys
curl "http://localhost:5000/api/regex/search?pattern=sk-%28%5B%5E%5Cs%5D%2B%29&text=API%20key%3A%20sk-1234567890abcdef"
# URL decoded: sk-([^\s]+)
```

**Attack Result:**
```json
{
  "matches": [
    {
      "value": "password=secret123",
      "groups": [
        {
          "value": "secret123",
          "index": 9
        }
      ]
    }
  ]
}
```

#### 3. Input Validation Bypass
```bash
# Bypass email validation by injecting malicious domain pattern
curl "http://localhost:5000/api/regex/validate-email?email=attacker@evil.com&domainPattern=%2E%2A"
# URL decoded domainPattern: .*

# The constructed pattern becomes: ^[a-zA-Z0-9._%+-]+@.*$
# This allows any domain, bypassing intended validation
```

#### 4. Log Data Extraction
```bash
# Extract all password entries from logs
curl "http://localhost:5000/api/regex/log-search?searchTerm=password%3D%5B%5E%5Cs%5D%2B&useRegex=true"
# URL decoded: password=[^\s]+

# Extract IP addresses
curl "http://localhost:5000/api/regex/log-search?searchTerm=%5Cd%7B1%2C3%7D%5C%2E%5Cd%7B1%2C3%7D%5C%2E%5Cd%7B1%2C3%7D%5C%2E%5Cd%7B1%2C3%7D&useRegex=true"
# URL decoded: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}

# Extract all tokens/keys
curl "http://localhost:5000/api/regex/log-search?searchTerm=%28sk-%7Cjwt-%7Capi-%29%5B%5E%5Cs%5D%2B&useRegex=true"
# URL decoded: (sk-|jwt-|api-)[^\s]+
```

#### 5. Advanced Regex Injection Techniques

**Unicode Exploitation:**
```bash
# Use Unicode properties for broad matching
curl "http://localhost:5000/api/regex/search?pattern=%5Cp%7BL%7D%2B&text=sensitive_data_here"
# URL decoded: \p{L}+ (matches any Unicode letter)
```

**Negative Lookahead Bypass:**
```bash
# Complex pattern to bypass simple filtering
curl "http://localhost:5000/api/regex/search?pattern=%28%3F%21notallowed%29%2E%2A&text=notallowed_but_matched_anyway"
# URL decoded: (?!notallowed).* (negative lookahead)
```

### Attack Methodology

#### Phase 1: Pattern Injection Testing
```bash
# Test if user input affects regex pattern
curl "http://localhost:5000/api/regex/search?pattern=test&text=testing"

# Test for error responses revealing regex engine
curl "http://localhost:5000/api/regex/search?pattern=%5B&text=test"  # Invalid pattern [
```

#### Phase 2: ReDoS Vulnerability Assessment
```bash
# Test for ReDoS susceptibility
curl "http://localhost:5000/api/regex/search?pattern=%5E%28a%2B%29%2Bb%24&text=aaaaaaaaaaaac"

# Measure response time to confirm ReDoS
time curl "http://localhost:5000/api/regex/search?pattern=%5E%28a%2A%29%2A%24&text=aaaaaaaaaaaab"
```

#### Phase 3: Information Extraction
```bash
# Extract sensitive patterns from accessible text
curl "http://localhost:5000/api/regex/search?pattern=%5Cw%2B%40%5Cw%2B%5C%2E%5Cw%2B&text=email%3A%20admin%40company.com%20password%3A%20secret"
# Pattern: \w+@\w+\.\w+ (email addresses)

# Extract API keys or tokens
curl "http://localhost:5000/api/regex/search?pattern=sk-%5B%5Cw%5D%2B&text=config%3A%20sk-1234567890abcdef"
# Pattern: sk-[\w]+ (Stripe-like API keys)
```

#### Phase 4: Validation Bypass
```bash
# Bypass domain validation
curl "http://localhost:5000/api/regex/validate-email?email=hacker@malicious.org&domainPattern=%2E%2A"

# Bypass length restrictions
curl "http://localhost:5000/api/regex/validate-email?email=test@test.com&domainPattern=%5E%2E%7B0%2C1000%7D%24"
# Pattern: ^.{0,1000}$ (allows any length)
```

## Impact Analysis

### Technical Impact
- **Denial of Service**: ReDoS attacks causing server unresponsiveness
- **Information Disclosure**: Extraction of sensitive data through pattern matching
- **Validation Bypass**: Circumventing security controls and input validation
- **Performance Degradation**: Slow regex processing affecting application performance

### Business Impact
- **Service Availability**: Application downtime due to ReDoS attacks
- **Data Breaches**: Exposure of sensitive information through regex extraction
- **Security Control Bypass**: Compromise of authentication and authorization mechanisms
- **Compliance Violations**: Unauthorized access to protected data

### Real-World Scenarios

#### Scenario 1: Log Analysis System
```
# Attacker extracts all database passwords from logs
Pattern: password=([^\s]+)
Result: Access to all database credentials logged by the system
```

#### Scenario 2: Email Validation Bypass
```
# Attacker bypasses domain restrictions
Original: ^[a-zA-Z0-9._%+-]+@company\.com$
Injected: ^[a-zA-Z0-9._%+-]+@.*$
Result: Any email domain accepted, bypassing security policy
```

## Fix Implementation

### 1. Predefined Pattern Approach

```csharp
public class SafeRegexController : ControllerBase
{
    // SECURE: Predefined, tested patterns with safe construction
    private static readonly Dictionary<string, RegexPattern> _allowedPatterns = new()
    {
        ["email"] = new RegexPattern(
            @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            "Email address validation"),
            
        ["phone"] = new RegexPattern(
            @"^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$",
            "Phone number validation"),
            
        ["username"] = new RegexPattern(
            @"^[a-zA-Z0-9_]{3,20}$",
            "Username validation"),
            
        ["ipaddress"] = new RegexPattern(
            @"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            "IP address validation"),
            
        ["url"] = new RegexPattern(
            @"^https?:\/\/[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+(?:\/[^\s]*)?$",
            "URL validation")
    };

    [HttpGet("validate-secure")]
    public IActionResult ValidateWithPredefinedPattern(string patternName, string text)
    {
        if (string.IsNullOrEmpty(patternName) || string.IsNullOrEmpty(text))
        {
            return BadRequest("Both patternName and text are required");
        }

        // SECURE: Only allow predefined patterns
        if (!_allowedPatterns.TryGetValue(patternName.ToLower(), out var regexPattern))
        {
            return BadRequest($"Pattern '{patternName}' not supported. Supported patterns: {string.Join(", ", _allowedPatterns.Keys)}");
        }

        // Input validation
        if (text.Length > 1000)
        {
            return BadRequest("Text input too long (max 1000 characters)");
        }

        try
        {
            var regex = new Regex(regexPattern.Pattern, RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));
            var isMatch = regex.IsMatch(text);
            
            return Ok(new
            {
                patternName = patternName,
                description = regexPattern.Description,
                text = text.Length > 100 ? text.Substring(0, 100) + "..." : text,
                isValid = isMatch,
                processingTime = "< 100ms",
                securityNote = "Using predefined, safe regex patterns"
            });
        }
        catch (RegexMatchTimeoutException)
        {
            _logger.LogWarning("Regex timeout for pattern '{Pattern}' with text length {Length}", 
                patternName, text.Length);
            return BadRequest("Pattern matching timeout");
        }
    }

    public class RegexPattern
    {
        public string Pattern { get; }
        public string Description { get; }

        public RegexPattern(string pattern, string description)
        {
            Pattern = pattern;
            Description = description;
        }
    }
}
```

### 2. Input Escaping Approach

```csharp
[HttpGet("search-secure")]
public IActionResult SearchSecure(string searchTerm, string text, bool exactMatch = false)
{
    if (string.IsNullOrEmpty(searchTerm) || string.IsNullOrEmpty(text))
    {
        return BadRequest("Both searchTerm and text are required");
    }

    // Input validation
    if (searchTerm.Length > 100 || text.Length > 10000)
    {
        return BadRequest("Input too long");
    }

    try
    {
        string pattern;
        
        if (exactMatch)
        {
            // SECURE: Escape all regex metacharacters in user input
            var escapedTerm = Regex.Escape(searchTerm);
            pattern = $@"\b{escapedTerm}\b"; // Word boundary match
        }
        else
        {
            // SECURE: Escape user input and allow simple wildcard
            var escapedTerm = Regex.Escape(searchTerm);
            pattern = escapedTerm.Replace(@"\*", ".*"); // Allow * as wildcard only
        }

        var regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));
        var matches = regex.Matches(text);

        var results = matches.Cast<Match>().Select(m => new
        {
            value = m.Value,
            index = m.Index,
            length = m.Length
        }).Take(50).ToList(); // Limit results

        return Ok(new
        {
            searchTerm = searchTerm,
            exactMatch = exactMatch,
            escapedPattern = pattern,
            matchCount = matches.Count,
            matches = results.Take(10), // Limit displayed results
            securityNote = "User input properly escaped to prevent regex injection"
        });
    }
    catch (RegexMatchTimeoutException)
    {
        _logger.LogWarning("Regex timeout for search term '{SearchTerm}'", searchTerm);
        return BadRequest("Search timeout - pattern too complex");
    }
    catch (ArgumentException ex)
    {
        _logger.LogWarning("Invalid regex pattern created from search term '{SearchTerm}': {Error}", 
            searchTerm, ex.Message);
        return BadRequest("Invalid search pattern");
    }
}
```

### 3. Alternative Validation Without Regex

```csharp
[HttpGet("validate-alternative")]
public IActionResult ValidateWithoutRegex(string validationType, string value)
{
    if (string.IsNullOrEmpty(validationType) || string.IsNullOrEmpty(value))
    {
        return BadRequest("Both validationType and value are required");
    }

    bool isValid;
    string method;

    switch (validationType.ToLower())
    {
        case "email":
            // SECURE: Use built-in email validation
            isValid = IsValidEmail(value);
            method = "Built-in MailAddress validation";
            break;

        case "phone":
            // SECURE: Use character-based validation
            isValid = IsValidPhone(value);
            method = "Character-based validation";
            break;

        case "url":
            // SECURE: Use Uri.TryCreate
            isValid = IsValidUrl(value);
            method = "Built-in Uri validation";
            break;

        case "ipaddress":
            // SECURE: Use IPAddress.TryParse
            isValid = IsValidIPAddress(value);
            method = "Built-in IPAddress validation";
            break;

        case "numeric":
            // SECURE: Use built-in parsing
            isValid = IsNumeric(value);
            method = "Built-in numeric parsing";
            break;

        default:
            return BadRequest($"Validation type '{validationType}' not supported");
    }

    return Ok(new
    {
        validationType = validationType,
        value = value,
        isValid = isValid,
        validationMethod = method,
        securityNote = "Using built-in validation methods instead of regex"
    });
}

private bool IsValidEmail(string email)
{
    try
    {
        var mailAddress = new System.Net.Mail.MailAddress(email);
        return mailAddress.Address == email;
    }
    catch
    {
        return false;
    }
}

private bool IsValidPhone(string phone)
{
    // Remove common formatting characters
    var digitsOnly = new string(phone.Where(char.IsDigit).ToArray());
    
    // US phone numbers: 10 or 11 digits (with country code)
    return digitsOnly.Length == 10 || digitsOnly.Length == 11;
}

private bool IsValidUrl(string url)
{
    return Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
           (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);
}

private bool IsValidIPAddress(string ipAddress)
{
    return System.Net.IPAddress.TryParse(ipAddress, out _);
}

private bool IsNumeric(string value)
{
    return decimal.TryParse(value, out _);
}
```

### 4. Secure Pattern Builder

```csharp
public class SecurePatternBuilder
{
    private readonly List<string> _allowedMetacharacters = new() { @"\d", @"\w", @"\s", ".", "*", "+", "?", "^", "$" };
    
    public string BuildSafePattern(string userInput, PatternType patternType)
    {
        // Validate user input first
        if (string.IsNullOrEmpty(userInput) || userInput.Length > 50)
        {
            throw new ArgumentException("Invalid input for pattern building");
        }

        // Check for dangerous patterns
        if (ContainsDangerousPattern(userInput))
        {
            throw new ArgumentException("Input contains dangerous regex patterns");
        }

        return patternType switch
        {
            PatternType.StartsWith => $"^{Regex.Escape(userInput)}",
            PatternType.EndsWith => $"{Regex.Escape(userInput)}$",
            PatternType.Contains => Regex.Escape(userInput),
            PatternType.ExactMatch => $"^{Regex.Escape(userInput)}$",
            PatternType.WordBoundary => $@"\b{Regex.Escape(userInput)}\b",
            _ => throw new ArgumentException("Invalid pattern type")
        };
    }

    private bool ContainsDangerousPattern(string input)
    {
        var dangerousPatterns = new[]
        {
            @"(.*)+", @"(.*)*", @"(.+)+", @"(.+)*",  // Catastrophic backtracking
            @"(a|a)*", @"(a+)+", @"(a*)*",           // ReDoS patterns
            @"(?=.*){10,}", @"(.{0,10}){10,}",       // Nested quantifiers
            @".*.*.*.*.*.*.*.*.*.*",                  // Excessive wildcards
        };

        return dangerousPatterns.Any(pattern => 
            input.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    public enum PatternType
    {
        StartsWith,
        EndsWith, 
        Contains,
        ExactMatch,
        WordBoundary
    }
}

[HttpGet("build-pattern")]
public IActionResult BuildSecurePattern(string userInput, string patternType)
{
    try
    {
        var builder = new SecurePatternBuilder();
        
        if (!Enum.TryParse<SecurePatternBuilder.PatternType>(patternType, true, out var type))
        {
            return BadRequest("Invalid pattern type");
        }

        var safePattern = builder.BuildSafePattern(userInput, type);
        
        return Ok(new
        {
            userInput = userInput,
            patternType = patternType,
            safePattern = safePattern,
            securityNote = "Pattern built with proper escaping and validation"
        });
    }
    catch (ArgumentException ex)
    {
        return BadRequest(new { error = ex.Message });
    }
}
```

### 5. Regex Injection Protection Middleware

```csharp
public class RegexInjectionProtectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RegexInjectionProtectionMiddleware> _logger;

    public RegexInjectionProtectionMiddleware(RequestDelegate next, ILogger<RegexInjectionProtectionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Check for regex injection patterns in parameters
        if (ContainsRegexInjectionAttempt(context.Request))
        {
            var clientIP = context.Connection.RemoteIpAddress?.ToString();
            _logger.LogWarning("Regex injection attempt detected from IP: {ClientIP} on path: {Path}", 
                clientIP, context.Request.Path);

            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Request contains potentially malicious regex patterns");
            return;
        }

        await _next(context);
    }

    private bool ContainsRegexInjectionAttempt(HttpRequest request)
    {
        var suspiciousPatterns = new[]
        {
            @"(.*)+", @"(.*)*", @"(.+)+", @"(.+)*",  // ReDoS patterns
            @"(a|a)*", @"(a+)+", @"(a*)*",           // Common ReDoS
            @"(?=.*){", @"(.{0,", @"){10,}",         // Nested quantifiers
            @".*.*.*.*.*.*.*.*.*.*",                  // Excessive wildcards
            @"\p{", @"\P{", @"\N{",                  // Unicode properties
            @"(?<", @"(?P<", @"(?'",                 // Named groups
            @"(?#", @"(?i:", @"(?s:",                // Inline modifiers
            @"\\k<", @"\\g<", @"\\g'",               // Backreferences
        };

        // Check query parameters
        foreach (var param in request.Query)
        {
            var value = param.Value.ToString();
            if (suspiciousPatterns.Any(pattern => value.Contains(pattern, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        // Check form data
        if (request.HasFormContentType)
        {
            foreach (var param in request.Form)
            {
                var value = param.Value.ToString();
                if (suspiciousPatterns.Any(pattern => value.Contains(pattern, StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
```

## How the Fixes Work

### 1. Predefined Patterns
```csharp
if (!_allowedPatterns.TryGetValue(patternName.ToLower(), out var regexPattern))
    return BadRequest($"Pattern '{patternName}' not supported");
```
- **Problem Solved**: Eliminates user control over regex patterns
- **How**: Only allows selection from predefined, tested patterns
- **Benefit**: Zero risk of regex injection or ReDoS

### 2. Input Escaping
```csharp
var escapedTerm = Regex.Escape(searchTerm);
```
- **Problem Solved**: Neutralizes regex metacharacters
- **How**: Escapes all special regex characters in user input
- **Benefit**: User input treated as literal text, not regex

### 3. Alternative Validation
```csharp
var mailAddress = new System.Net.Mail.MailAddress(email);
return mailAddress.Address == email;
```
- **Problem Solved**: Avoids regex completely for common validations
- **How**: Uses built-in .NET validation methods
- **Benefit**: No regex complexity, better performance, immune to injection

### 4. Timeout Protection
```csharp
var regex = new Regex(pattern, RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));
```
- **Problem Solved**: Prevents ReDoS attacks even with malicious patterns
- **How**: Hard timeout limit on regex execution
- **Benefit**: Bounded execution time regardless of pattern complexity

### 5. Pattern Validation
```csharp
if (ContainsDangerousPattern(userInput))
    throw new ArgumentException("Input contains dangerous regex patterns");
```
- **Problem Solved**: Detects and blocks known dangerous patterns
- **How**: Scans input for ReDoS and injection patterns
- **Benefit**: Proactive protection against common attack patterns

## Advanced Protection Techniques

### 1. Regex Complexity Analysis
```csharp
public class RegexComplexityAnalyzer
{
    public RegexComplexityResult AnalyzePattern(string pattern)
    {
        var result = new RegexComplexityResult();
        
        // Count nested quantifiers
        result.NestedQuantifiers = CountNestedQuantifiers(pattern);
        
        // Count alternations
        result.Alternations = CountAlternations(pattern);
        
        // Check for catastrophic backtracking patterns
        result.HasCatastrophicBacktracking = HasCatastrophicBacktracking(pattern);
        
        // Calculate overall complexity score
        result.ComplexityScore = CalculateComplexityScore(result);
        
        return result;
    }

    private int CountNestedQuantifiers(string pattern)
    {
        var count = 0;
        var inGroup = false;
        var groupDepth = 0;
        
        for (int i = 0; i < pattern.Length; i++)
        {
            if (pattern[i] == '(' && (i == 0 || pattern[i-1] != '\\'))
            {
                inGroup = true;
                groupDepth++;
            }
            else if (pattern[i] == ')' && (i == 0 || pattern[i-1] != '\\'))
            {
                groupDepth--;
                if (groupDepth == 0) inGroup = false;
            }
            else if (inGroup && (pattern[i] == '+' || pattern[i] == '*' || pattern[i] == '?'))
            {
                // Check if this quantifier is followed by another quantifier
                if (i + 1 < pattern.Length && (pattern[i+1] == '+' || pattern[i+1] == '*' || pattern[i+1] == '?'))
                {
                    count++;
                }
            }
        }
        
        return count;
    }

    private bool HasCatastrophicBacktracking(string pattern)
    {
        var dangerousPatterns = new[]
        {
            @"\(\.\*\)\+", @"\(\.\*\)\*", @"\(\.\+\)\+", @"\(\.\+\)\*",
            @"\([^)]*\|[^)]*\)\*", @"\([^)]*\+\)\+", @"\([^)]*\*\)\*"
        };

        return dangerousPatterns.Any(dangerous => 
            Regex.IsMatch(pattern, dangerous, RegexOptions.IgnoreCase));
    }

    private int CalculateComplexityScore(RegexComplexityResult result)
    {
        var score = 0;
        score += result.NestedQuantifiers * 10;
        score += result.Alternations * 2;
        if (result.HasCatastrophicBacktracking) score += 50;
        return score;
    }

    public class RegexComplexityResult
    {
        public int NestedQuantifiers { get; set; }
        public int Alternations { get; set; }
        public bool HasCatastrophicBacktracking { get; set; }
        public int ComplexityScore { get; set; }
        public bool IsHighRisk => ComplexityScore > 20;
    }
}

[HttpGet("analyze-pattern")]
public IActionResult AnalyzePatternComplexity(string pattern)
{
    if (string.IsNullOrEmpty(pattern))
        return BadRequest("Pattern is required");

    try
    {
        var analyzer = new RegexComplexityAnalyzer();
        var analysis = analyzer.AnalyzePattern(pattern);

        if (analysis.IsHighRisk)
        {
            _logger.LogWarning("High-risk regex pattern detected: {Pattern}", pattern);
            return BadRequest(new
            {
                error = "Pattern complexity too high",
                analysis = analysis,
                recommendation = "Use simpler patterns or alternative validation methods"
            });
        }

        return Ok(new
        {
            pattern = pattern,
            analysis = analysis,
            status = "Pattern complexity acceptable"
        });
    }
    catch (Exception ex)
    {
        return BadRequest(new { error = "Pattern analysis failed", details = ex.Message });
    }
}
```

### 2. Safe Regex Compilation Service
```csharp
public class SafeRegexService
{
    private readonly IMemoryCache _regexCache;
    private readonly ILogger<SafeRegexService> _logger;
    private readonly Dictionary<string, Regex> _precompiledPatterns;

    public SafeRegexService(IMemoryCache memoryCache, ILogger<SafeRegexService> logger)
    {
        _regexCache = memoryCache;
        _logger = logger;
        _precompiledPatterns = InitializePrecompiledPatterns();
    }

    public RegexResult ExecutePattern(string patternName, string input, RegexOptions options = RegexOptions.None)
    {
        if (string.IsNullOrEmpty(patternName) || string.IsNullOrEmpty(input))
        {
            return new RegexResult { Success = false, ErrorMessage = "Pattern name and input are required" };
        }

        // Check if pattern exists in precompiled patterns
        if (!_precompiledPatterns.TryGetValue(patternName, out var regex))
        {
            return new RegexResult { Success = false, ErrorMessage = $"Pattern '{patternName}' not found" };
        }

        try
        {
            var startTime = DateTime.UtcNow;
            var matches = regex.Matches(input);
            var executionTime = DateTime.UtcNow - startTime;

            // Log slow patterns
            if (executionTime.TotalMilliseconds > 50)
            {
                _logger.LogWarning("Slow regex execution: Pattern '{Pattern}' took {ExecutionTime}ms", 
                    patternName, executionTime.TotalMilliseconds);
            }

            return new RegexResult
            {
                Success = true,
                Matches = matches.Cast<Match>().Select(m => new RegexMatch
                {
                    Value = m.Value,
                    Index = m.Index,
                    Length = m.Length,
                    Groups = m.Groups.Cast<Group>().Skip(1).Select(g => g.Value).ToList()
                }).ToList(),
                ExecutionTime = executionTime.TotalMilliseconds,
                PatternName = patternName
            };
        }
        catch (RegexMatchTimeoutException)
        {
            _logger.LogWarning("Regex timeout for pattern '{Pattern}'", patternName);
            return new RegexResult { Success = false, ErrorMessage = "Pattern execution timeout" };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Regex execution error for pattern '{Pattern}'", patternName);
            return new RegexResult { Success = false, ErrorMessage = "Pattern execution failed" };
        }
    }

    private Dictionary<string, Regex> InitializePrecompiledPatterns()
    {
        var patterns = new Dictionary<string, Regex>();

        var patternDefinitions = new Dictionary<string, string>
        {
            ["email"] = @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            ["phone_us"] = @"^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$",
            ["ipv4"] = @"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            ["url_http"] = @"^https?:\/\/[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+(?:\/[^\s]*)?$",
            ["username"] = @"^[a-zA-Z0-9_]{3,20}$",
            ["password_strong"] = @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
            ["credit_card"] = @"^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})$",
            ["ssn"] = @"^(?!666|000|9\d{2})\d{3}-?(?!00)\d{2}-?(?!0{4})\d{4}$"
        };

        foreach (var kvp in patternDefinitions)
        {
            try
            {
                patterns[kvp.Key] = new Regex(kvp.Value, 
                    RegexOptions.Compiled | RegexOptions.IgnoreCase, 
                    TimeSpan.FromMilliseconds(100));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to compile regex pattern '{Pattern}'", kvp.Key);
            }
        }

        return patterns;
    }

    public class RegexResult
    {
        public bool Success { get; set; }
        public List<RegexMatch> Matches { get; set; } = new();
        public string ErrorMessage { get; set; } = string.Empty;
        public double ExecutionTime { get; set; }
        public string PatternName { get; set; } = string.Empty;
    }

    public class RegexMatch
    {
        public string Value { get; set; } = string.Empty;
        public int Index { get; set; }
        public int Length { get; set; }
        public List<string> Groups { get; set; } = new();
    }
}
```

### 3. Input Sanitization and Validation
```csharp
public class RegexInputValidator
{
    private readonly ILogger<RegexInputValidator> _logger;

    public RegexInputValidator(ILogger<RegexInputValidator> logger)
    {
        _logger = logger;
    }

    public ValidationResult ValidateRegexInput(string input, string context)
    {
        var result = new ValidationResult();

        // Basic input validation
        if (string.IsNullOrEmpty(input))
        {
            result.IsValid = false;
            result.ErrorMessage = "Input cannot be empty";
            return result;
        }

        // Length validation
        if (input.Length > 1000)
        {
            result.IsValid = false;
            result.ErrorMessage = "Input too long (max 1000 characters)";
            return result;
        }

        // Character validation
        if (ContainsInvalidCharacters(input))
        {
            result.IsValid = false;
            result.ErrorMessage = "Input contains invalid characters";
            return result;
        }

        // Pattern injection detection
        if (ContainsRegexInjectionPatterns(input))
        {
            result.IsValid = false;
            result.ErrorMessage = "Input contains potentially malicious regex patterns";
            _logger.LogWarning("Regex injection attempt detected in context '{Context}': {Input}", 
                context, input);
            return result;
        }

        // ReDoS pattern detection
        if (ContainsReDoSPatterns(input))
        {
            result.IsValid = false;
            result.ErrorMessage = "Input contains patterns that could cause performance issues";
            _logger.LogWarning("Potential ReDoS pattern detected in context '{Context}': {Input}", 
                context, input);
            return result;
        }

        result.IsValid = true;
        result.SanitizedInput = SanitizeInput(input);
        return result;
    }

    private bool ContainsInvalidCharacters(string input)
    {
        // Check for null bytes and control characters
        return input.Any(c => c == '\0' || (char.IsControl(c) && c != '\t' && c != '\n' && c != '\r'));
    }

    private bool ContainsRegexInjectionPatterns(string input)
    {
        var injectionPatterns = new[]
        {
            @"(.*)+", @"(.*)*", @"(.+)+", @"(.+)*",
            @"(a|a)*", @"(a+)+", @"(a*)*",
            @"(?=.*){", @"(.{0,", @"){10,}",
            @"\p{", @"\P{", @"\N{",
            @"(?<", @"(?P<", @"(?'",
            @"(?#", @"(?i:", @"(?s:",
            @"\\k<", @"\\g<", @"\\g'"
        };

        return injectionPatterns.Any(pattern => 
            input.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    private bool ContainsReDoSPatterns(string input)
    {
        var redosPatterns = new[]
        {
            @"(\w+\s?)*", @"([a-zA-Z]+)*", @"(\d+)*",
            @"(.*a){10,}", @"(.{0,10}){10,}",
            @".*.*.*.*.*.*.*.*.*.*",
            @"(x+x+)+", @"([a-z]+)+", @"(\w*)*"
        };

        return redosPatterns.Any(pattern => 
            input.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    private string SanitizeInput(string input)
    {
        // Remove or escape potentially dangerous characters
        return input
            .Replace("\0", "") // Remove null bytes
            .Replace("\r\n", " ") // Replace line breaks with spaces
            .Replace("\n", " ")
            .Replace("\r", " ")
            .Trim();
    }

    public class ValidationResult
    {
        public bool IsValid { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
        public string SanitizedInput { get; set; } = string.Empty;
    }
}
```

## Performance Monitoring and Alerting

### 1. Regex Performance Monitor
```csharp
public class RegexPerformanceMonitor
{
    private readonly ILogger<RegexPerformanceMonitor> _logger;
    private readonly IMetrics _metrics;

    public RegexPerformanceMonitor(ILogger<RegexPerformanceMonitor> logger, IMetrics metrics)
    {
        _logger = logger;
        _metrics = metrics;
    }

    public void MonitorRegexExecution(string patternName, string input, TimeSpan executionTime, bool success)
    {
        // Record metrics
        _metrics.RecordGauge("regex_execution_time_ms", executionTime.TotalMilliseconds, 
            new[] { new KeyValuePair<string, string>("pattern", patternName) });

        _metrics.IncrementCounter("regex_executions_total", 
            new[] { 
                new KeyValuePair<string, string>("pattern", patternName),
                new KeyValuePair<string, string>("success", success.ToString())
            });

        // Alert on slow executions
        if (executionTime.TotalMilliseconds > 100)
        {
            _logger.LogWarning("Slow regex execution detected: Pattern '{Pattern}' took {ExecutionTime}ms with input length {InputLength}", 
                patternName, executionTime.TotalMilliseconds, input.Length);
        }

        // Alert on very slow executions (potential ReDoS)
        if (executionTime.TotalMilliseconds > 1000)
        {
            _logger.LogError("Potential ReDoS attack detected: Pattern '{Pattern}' took {ExecutionTime}ms", 
                patternName, executionTime.TotalMilliseconds);
            
            // Could trigger additional security measures here
            TriggerSecurityAlert(patternName, executionTime, input.Length);
        }
    }

    private void TriggerSecurityAlert(string patternName, TimeSpan executionTime, int inputLength)
    {
        // Implementation would depend on your alerting system
        // Examples: Send to security team, block IP, etc.
        _logger.LogCritical("SECURITY ALERT: ReDoS attack detected - Pattern: {Pattern}, Time: {Time}ms, InputLength: {Length}", 
            patternName, executionTime.TotalMilliseconds, inputLength);
    }
}
```

## Testing the Fix

### Positive Tests (Should Work)
```bash
# Valid predefined patterns
curl "http://localhost:5000/api/regex/validate-secure?patternName=email&text=user@example.com"
curl "http://localhost:5000/api/regex/validate-secure?patternName=phone&text=555-123-4567"

# Safe search with escaping
curl "http://localhost:5000/api/regex/search-secure?searchTerm=user@example.com&text=Contact%20user@example.com%20for%20info"

# Alternative validation
curl "http://localhost:5000/api/regex/validate-alternative?validationType=email&value=test@test.com"
```

### Security Tests (Should Be Blocked)
```bash
# ReDoS patterns should be blocked
curl "http://localhost:5000/api/regex/validate-secure?patternName=malicious&text=test"

# Injection attempts should be blocked
curl "http://localhost:5000/api/regex/search-secure?searchTerm=%28.*%29%2B&text=test"

# Complex patterns should be rejected
curl "http://localhost:5000/api/regex/analyze-pattern?pattern=%5E%28a%2B%29%2Bb%24"
```

### Performance Tests
```bash
# Monitor execution times
time curl "http://localhost:5000/api/regex/validate-secure?patternName=email&text=user@example.com"

# Test timeout protection
curl "http://localhost:5000/api/regex/search-secure?searchTerm=test&text=$(python -c 'print("a"*10000)')"
```

## Conclusion

Regular Expression Injection is a serious vulnerability that can lead to denial of service, information disclosure, and security control bypass. The comprehensive fix approach includes:

1. **Elimination of User Pattern Control**: Use predefined patterns instead of user-supplied regex
2. **Input Escaping**: Properly escape user input when used in regex contexts
3. **Alternative Validation**: Use built-in validation methods instead of regex where possible
4. **Timeout Protection**: Implement strict timeouts to prevent ReDoS attacks
5. **Pattern Analysis**: Analyze patterns for complexity and dangerous constructs
6. **Monitoring and Alerting**: Track regex performance and detect potential attacks

By implementing these protections, applications can safely use regular expressions without exposing themselves to injection attacks while maintaining the functionality users expect.
