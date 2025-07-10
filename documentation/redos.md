# Regular Expression Denial of Service (ReDoS) - Deep Dive

## What is ReDoS?

Regular Expression Denial of Service (ReDoS) is a vulnerability where poorly constructed regular expressions can cause catastrophic backtracking, leading to exponential time complexity. This allows attackers to cause excessive CPU usage and potentially crash applications with carefully crafted input strings.

## Root Cause Analysis

### Understanding Catastrophic Backtracking

#### Vulnerable Pattern Example
```csharp
// VULNERABLE: Nested quantifiers cause exponential backtracking
var pattern = @"^(a+)+b$";
var regex = new Regex(pattern);
var isValid = regex.IsMatch("aaaaaaaaaaaaaaaaaaaaac"); // Hangs indefinitely
```

**Why This Pattern is Dangerous:**
- `(a+)+` creates nested quantifiers
- Inner `a+` matches one or more 'a' characters
- Outer `+` repeats the group one or more times
- When input doesn't match (ends with 'c' instead of 'b'), the engine tries every possible combination

#### Backtracking Explosion Visualization

For input `"aaaaaac"` with pattern `^(a+)+b$`:

```
Attempt 1: (aaaaaa) + fail on 'c'
Attempt 2: (aaaaa)(a) + fail on 'c'  
Attempt 3: (aaaa)(aa) + fail on 'c'
Attempt 4: (aaaa)(a)(a) + fail on 'c'
Attempt 5: (aaa)(aaa) + fail on 'c'
Attempt 6: (aaa)(aa)(a) + fail on 'c'
... and so on exponentially
```

For n characters, the regex engine makes approximately 2^n attempts.

### Vulnerable Code in the Application

#### 1. Basic ReDoS Pattern
```csharp
[HttpGet("validate")]
public IActionResult ValidateInput(string input)
{
    try
    {
        // VULNERABLE: Catastrophic backtracking regex pattern
        var pattern = @"^(a+)+b$";
        var regex = new Regex(pattern);

        // This will hang with input like "aaaaaaaaaaaaaaaaaaaaaac"
        var isValid = regex.IsMatch(input);

        return Ok(new { input, isValid, pattern });
    }
    catch (RegexMatchTimeoutException)
    {
        return StatusCode(500, "Regex timeout occurred");
    }
}
```

**Problems:**
- No timeout protection
- Vulnerable nested quantifier pattern
- Direct user input processing

#### 2. User-Controlled Regex Patterns
```csharp
[HttpGet("regex-validate")]
public IActionResult RegexValidate(string input, string customPattern = null)
{
    string pattern;
    if (!string.IsNullOrEmpty(customPattern))
    {
        // VULNERABLE: User can provide their own catastrophic regex patterns
        pattern = customPattern;
    }
    else
    {
        var vulnerablePatterns = new[]
        {
            @"^(a+)+b$",                    // Classic ReDoS
            @"^(a|a)*b$",                   // Alternation ReDoS
            @"^([a-zA-Z]+)*$",              // Character class ReDoS
            @"^(.*a){10,}$",                // Nested quantifier ReDoS
        };
        pattern = vulnerablePatterns[0];
    }

    // VULNERABLE: No timeout protection
    var regex = new Regex(pattern);
    var isValid = regex.IsMatch(input);
    
    return Ok(new { input, pattern, isValid });
}
```

**Additional Problems:**
- User can supply arbitrary regex patterns
- Built-in patterns are all vulnerable
- No input sanitization

#### 3. Complex Email Validation ReDoS
```csharp
[HttpGet("multi-validate")]
public IActionResult MultiRegexValidation(string email, string phone, string ssn)
{
    if (!string.IsNullOrEmpty(email))
    {
        // VULNERABLE: Complex email regex prone to ReDoS
        var emailPattern = @"^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$";
        var emailRegex = new Regex(emailPattern);
        // This can hang with input like "a@a.aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        results.Add(new { field = "email", isValid = emailRegex.IsMatch(email) });
    }
}
```

## How ReDoS Attacks Work

### Attack Vectors

#### 1. Basic Nested Quantifier Attack
```bash
# Attack the basic validation endpoint
curl "http://localhost:5000/api/regex/validate?input=aaaaaaaaaaaaaaaaaaaaac"
```

**What happens:**
1. Server receives input with 20 'a' characters followed by 'c'
2. Regex engine tries to match `^(a+)+b$` pattern
3. Since it ends with 'c' not 'b', engine backtracks through all combinations
4. With 20 characters, engine makes ~2^20 = 1,048,576 attempts
5. CPU usage spikes to 100%, response times out

#### 2. Custom Pattern Injection
```bash
# Inject custom catastrophic pattern
curl "http://localhost:5000/api/vulnerable/regex-validate?input=aaaaaaaaaaaac&customPattern=%5E%28a%2B%29%2Bb%24"
```

**URL Decoded Pattern:** `^(a+)+b$`

**Attack Flow:**
1. Attacker provides both malicious input and malicious pattern
2. Server constructs regex with user-supplied pattern
3. Pattern causes exponential backtracking
4. Server becomes unresponsive

#### 3. Email Validation Attack
```bash
# Attack email validation with ReDoS payload
curl "http://localhost:5000/api/vulnerable/multi-regex?email=a@a.aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
```

**What happens:**
1. Email pattern has nested quantifiers: `([a-zA-Z0-9\-])+\.)+`
2. Input has many 'a' characters after the dot
3. Engine tries to match the pattern in multiple ways
4. Causes exponential backtracking and CPU exhaustion

#### 4. Amplification Attacks
```bash
# Multiple simultaneous requests to amplify impact
for i in {1..10}; do
    curl "http://localhost:5000/api/regex/validate?input=aaaaaaaaaaaaaaaaaaaaac" &
done
```

**Impact:**
- Multiple threads each consuming 100% CPU
- Server becomes completely unresponsive
- Potential application crash or timeout

### Attack Payload Construction

#### Calculating Attack Complexity
```
Pattern: ^(a+)+b$
Input: "a" * n + "c"

Time Complexity: O(2^n)
For n=20: ~1 million operations
For n=25: ~33 million operations  
For n=30: ~1 billion operations
```

#### Common Vulnerable Patterns
```regex
^(a+)+$           # Nested quantifiers
^(a|a)*$          # Alternation repetition  
^(a*)*$           # Star quantifier repetition
^(a+)+\w$         # Quantifier before character class
^([a-z]+)*$       # Character class repetition
```

## Impact Analysis

### Performance Impact
- **CPU Exhaustion**: Single request can consume 100% CPU
- **Memory Usage**: Regex engine allocates memory for backtracking
- **Thread Starvation**: Long-running regex blocks request threads
- **Cascading Failures**: Slow responses cause connection pool exhaustion

### Business Impact
- **Service Unavailability**: Application becomes unresponsive
- **Resource Costs**: Increased server resource consumption
- **User Experience**: Timeouts and slow responses
- **Security Monitoring**: False positives in monitoring systems

### Attack Characteristics
```csharp
// Demonstration of exponential growth
var pattern = @"^(a+)+b$";
var inputs = new[] { "aaac", "aaaaac", "aaaaaac", "aaaaaaac" };

// Results (approximate):
// "aaac"      -> 16 operations    (2^4)
// "aaaaac"    -> 32 operations    (2^5)  
// "aaaaaac"   -> 64 operations    (2^6)
// "aaaaaaac"  -> 128 operations   (2^7)
```

## Fix Implementation

### 1. Timeout Protection

```csharp
[HttpGet("validate-secure")]
public IActionResult ValidateInputSecure(string input)
{
    if (string.IsNullOrEmpty(input))
        return BadRequest("Input parameter is required");

    try
    {
        // SECURE: Use safe pattern with timeout
        var pattern = @"^[a-zA-Z0-9]+$"; // Simple, linear pattern
        var timeout = TimeSpan.FromMilliseconds(100); // 100ms max
        var regex = new Regex(pattern, RegexOptions.None, timeout);
        
        var isValid = regex.IsMatch(input);
        
        return Ok(new 
        { 
            input = input.Length > 50 ? input.Substring(0, 50) + "..." : input,
            isValid,
            processingNote = "Validated with timeout protection"
        });
    }
    catch (RegexMatchTimeoutException)
    {
        // Log potential ReDoS attempt
        _logger.LogWarning("Regex timeout for input length {Length} from IP {ClientIP}", 
            input.Length, HttpContext.Connection.RemoteIpAddress);
            
        return BadRequest("Input validation timeout - pattern too complex");
    }
}
```

### 2. Precompiled Safe Patterns

```csharp
public class SafeRegexValidator
{
    // Precompiled, tested safe patterns with timeouts
    private static readonly Dictionary<string, Regex> _safePatterns = new()
    {
        ["email"] = new Regex(
            @"^[^\s@]+@[^\s@]+\.[^\s@]+$", 
            RegexOptions.Compiled, 
            TimeSpan.FromMilliseconds(100)),
            
        ["phone"] = new Regex(
            @"^\d{3}-\d{3}-\d{4}$", 
            RegexOptions.Compiled, 
            TimeSpan.FromMilliseconds(50)),
            
        ["alphanumeric"] = new Regex(
            @"^[a-zA-Z0-9]+$", 
            RegexOptions.Compiled, 
            TimeSpan.FromMilliseconds(50)),
            
        ["username"] = new Regex(
            @"^[a-zA-Z0-9_]{3,20}$", 
            RegexOptions.Compiled, 
            TimeSpan.FromMilliseconds(50))
    };

    [HttpGet("validate-field")]
    public IActionResult ValidateField(string fieldType, string value)
    {
        if (string.IsNullOrEmpty(fieldType) || string.IsNullOrEmpty(value))
            return BadRequest("Both fieldType and value are required");

        // Input size limit
        if (value.Length > 1000)
            return BadRequest("Input too long");

        if (!_safePatterns.TryGetValue(fieldType.ToLower(), out var regex))
            return BadRequest($"Unsupported field type. Supported: {string.Join(", ", _safePatterns.Keys)}");

        try
        {
            var isValid = regex.IsMatch(value);
            return Ok(new 
            { 
                fieldType, 
                value = value.Length > 100 ? value.Substring(0, 100) + "..." : value,
                isValid,
                pattern = "Predefined safe pattern"
            });
        }
        catch (RegexMatchTimeoutException)
        {
            _logger.LogWarning("Regex timeout for field {FieldType} with input length {Length}", 
                fieldType, value.Length);
            return BadRequest("Validation timeout");
        }
    }
}
```

### 3. Alternative Validation Methods

```csharp
[HttpGet("validate-email-secure")]
public IActionResult ValidateEmailSecure(string email)
{
    if (string.IsNullOrEmpty(email))
        return BadRequest("Email parameter is required");

    try
    {
        // SECURE: Use built-in .NET email validation instead of regex
        var mailAddress = new System.Net.Mail.MailAddress(email);
        var isValid = mailAddress.Address == email;
        
        return Ok(new 
        { 
            email, 
            isValid,
            method = "Built-in .NET MailAddress validation"
        });
    }
    catch (FormatException)
    {
        return Ok(new 
        { 
            email, 
            isValid = false,
            method = "Built-in .NET MailAddress validation"
        });
    }
}

[HttpGet("validate-phone-secure")]
public IActionResult ValidatePhoneSecure(string phone)
{
    if (string.IsNullOrEmpty(phone))
        return BadRequest("Phone parameter is required");

    // SECURE: Simple string operations instead of regex
    var digitsOnly = new string(phone.Where(char.IsDigit).ToArray());
    var isValid = digitsOnly.Length == 10 || digitsOnly.Length == 11;
    
    return Ok(new 
    { 
        phone, 
        isValid,
        method = "Character-based validation"
    });
}
```

### 4. Input Sanitization and Rate Limiting

```csharp
public class ReDoSProtectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IMemoryCache _cache;
    private readonly ILogger<ReDoSProtectionMiddleware> _logger;

    public ReDoSProtectionMiddleware(RequestDelegate next, IMemoryCache cache, 
        ILogger<ReDoSProtectionMiddleware> logger)
    {
        _next = next;
        _cache = cache;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Check for potential ReDoS patterns in query parameters
        foreach (var param in context.Request.Query)
        {
            if (ContainsSuspiciousPattern(param.Value))
            {
                var clientIp = context.Connection.RemoteIpAddress?.ToString();
                var cacheKey = $"redos_attempt_{clientIp}";
                
                var attemptCount = _cache.Get<int>(cacheKey);
                attemptCount++;
                
                _cache.Set(cacheKey, attemptCount, TimeSpan.FromHours(1));
                
                if (attemptCount > 5)
                {
                    _logger.LogWarning("Multiple ReDoS attempts from IP {ClientIP}", clientIp);
                    context.Response.StatusCode = 429; // Too Many Requests
                    await context.Response.WriteAsync("Too many suspicious requests");
                    return;
                }
                
                _logger.LogWarning("Potential ReDoS pattern detected from IP {ClientIP}: {Pattern}", 
                    clientIp, param.Value.ToString());
            }
        }

        await _next(context);
    }

    private bool ContainsSuspiciousPattern(string input)
    {
        if (string.IsNullOrEmpty(input) || input.Length > 1000)
            return true;

        // Check for repeated characters that could cause ReDoS
        var repeatedCharPattern = @"(.)\1{10,}"; // 10+ repeated characters
        return Regex.IsMatch(input, repeatedCharPattern, RegexOptions.None, TimeSpan.FromMilliseconds(10));
    }
}
```

## How the Fixes Work

### 1. Timeout Protection
```csharp
var regex = new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100));
```
- **Problem Solved**: Prevents infinite hangs
- **How**: Regex engine stops processing after timeout
- **Trade-off**: Some complex legitimate inputs might timeout

### 2. Safe Pattern Design
```csharp
// UNSAFE: ^(a+)+b$
// SAFE:   ^[a-zA-Z0-9]+$
```
- **Problem Solved**: Eliminates catastrophic backtracking
- **How**: Uses linear-time patterns without nested quantifiers
- **Pattern Guidelines**:
  - Avoid nested quantifiers like `(a+)+`
  - Avoid alternation with overlap like `(a|a)*`
  - Use character classes instead of alternation

### 3. Precompiled Patterns
```csharp
RegexOptions.Compiled
```
- **Problem Solved**: Improves performance and safety
- **How**: Patterns are validated and optimized at compile time
- **Benefit**: Faster execution and early detection of problematic patterns

### 4. Input Size Limits
```csharp
if (value.Length > 1000)
    return BadRequest("Input too long");
```
- **Problem Solved**: Limits potential attack impact
- **How**: Restricts input size before regex processing
- **Calculation**: Even with ReDoS, limited input size bounds the attack

### 5. Alternative Validation
```csharp
var mailAddress = new System.Net.Mail.MailAddress(email);
```
- **Problem Solved**: Eliminates regex entirely for some validations
- **How**: Uses built-in .NET validation methods
- **Benefit**: No regex complexity, better performance

## Pattern Safety Analysis

### Safe Patterns (Linear Time)
```regex
^[a-zA-Z0-9]+$                    # Character class only
^\d{3}-\d{3}-\d{4}$              # Fixed repetition
^[a-z]+@[a-z]+\.[a-z]+$          # Simple structure
```

### Dangerous Patterns (Exponential Time)
```regex
^(a+)+$                          # Nested quantifiers
^(a|a)*$                         # Overlapping alternation
^(.*a){x,}$                      # Nested dot with quantifier
^([a-z]+)*$                      # Quantified character class
```

### Pattern Testing
```csharp
public static class RegexSafetyTester
{
    public static bool IsPatternSafe(string pattern, int maxTestLength = 50)
    {
        try
        {
            var regex = new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100));
            
            // Test with various problematic inputs
            var testInputs = new[]
            {
                new string('a', maxTestLength) + "b",
                new string('a', maxTestLength) + "c", 
                new string('a', maxTestLength),
                string.Concat(Enumerable.Repeat("ab", maxTestLength/2))
            };

            foreach (var input in testInputs)
            {
                var startTime = DateTime.UtcNow;
                regex.IsMatch(input);
                var elapsed = DateTime.UtcNow - startTime;
                
                if (elapsed.TotalMilliseconds > 50) // Suspicious if takes >50ms
                    return false;
            }
            
            return true;
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false; // Invalid pattern
        }
    }
}
```

## Testing the Fix

### Performance Testing
```bash
# Safe endpoint - should respond quickly
time curl "http://localhost:5000/api/regex/validate-secure?input=aaaaaaaaaaaaaaaaaaaaaac"

# Should complete in <200ms even with long input
time curl "http://localhost:5000/api/regex/validate-field?fieldType=alphanumeric&value=$(python -c 'print("a"*100)')"
```

### Timeout Testing
```bash
# Should timeout gracefully with error message
curl "http://localhost:5000/api/regex/validate-secure?input=$(python -c 'print("a"*1000 + "c")')"
```

### Rate Limiting Testing
```bash
# Multiple suspicious requests should trigger rate limiting
for i in {1..10}; do
    curl "http://localhost:5000/api/regex/validate-secure?input=$(python -c 'print("a"*50 + "c")')" &
done
```

The comprehensive fix ensures that ReDoS attacks are mitigated through multiple layers of protection: timeouts, safe patterns, input validation, and alternative validation methods where possible.
