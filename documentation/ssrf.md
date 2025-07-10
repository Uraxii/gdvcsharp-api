# Server-Side Request Forgery (SSRF) - Deep Dive

## What is SSRF?

Server-Side Request Forgery (SSRF) is a vulnerability where an attacker can make the server perform HTTP requests to arbitrary destinations. This allows attackers to bypass network-level protections and access internal services that should not be publicly accessible.

## Root Cause Analysis

### Vulnerable Code in `SsrfController.cs`

```csharp
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
```

### Why This Code is Vulnerable

1. **No URL Validation**: The code accepts any URL string without validation
2. **Direct HTTP Request**: Uses `HttpClient.GetStringAsync()` directly with user input
3. **No Network Restrictions**: No checks for private IP ranges, localhost, or internal services
4. **Full Response Return**: Returns the complete response content to the attacker

## How the Exploit Works

### Attack Vectors

#### 1. Internal Network Scanning
```bash
# Scan internal network ranges
curl "http://localhost:5000/api/ssrf/vulnerable?url=http://192.168.1.1"
curl "http://localhost:5000/api/ssrf/vulnerable?url=http://10.0.0.1"
curl "http://localhost:5000/api/ssrf/vulnerable?url=http://172.16.0.1"
```

**What happens:**
- Server makes HTTP requests to internal IP addresses
- Attacker discovers which internal hosts are alive
- Can map internal network topology

#### 2. Localhost Services Access
```bash
# Access local services
curl "http://localhost:5000/api/ssrf/vulnerable?url=http://localhost:8080/admin"
curl "http://localhost:5000/api/ssrf/vulnerable?url=http://127.0.0.1:3306"
```

**What happens:**
- Bypasses firewall rules that block external access
- Accesses services running on localhost
- Can interact with databases, admin panels, or internal APIs

#### 3. Cloud Metadata Exploitation
```bash
# AWS metadata service
curl "http://localhost:5000/api/ssrf/vulnerable?url=http://169.254.169.254/latest/meta-data/"
curl "http://localhost:5000/api/ssrf/vulnerable?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Azure metadata service
curl "http://localhost:5000/api/ssrf/vulnerable?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

**What happens:**
- Accesses cloud provider metadata services
- Can retrieve IAM credentials, instance information
- Leads to cloud account compromise

#### 4. Protocol Smuggling
```bash
# File protocol (if supported)
curl "http://localhost:5000/api/ssrf/vulnerable?url=file:///etc/passwd"

# FTP protocol
curl "http://localhost:5000/api/ssrf/vulnerable?url=ftp://internal-ftp-server/sensitive-files/"
```

**What happens:**
- Uses different protocols beyond HTTP/HTTPS
- Can read local files or access FTP servers
- Bypasses HTTP-specific protections

### Step-by-Step Attack Flow

1. **Discovery**: Attacker identifies the SSRF endpoint
2. **Reconnaissance**: Tests various internal IP ranges and ports
3. **Service Enumeration**: Discovers running services and their responses
4. **Exploitation**: Accesses sensitive services or data
5. **Lateral Movement**: Uses gained access to compromise other systems

## Impact Analysis

### Immediate Risks
- **Internal Service Access**: Bypass firewall protections
- **Data Exfiltration**: Access internal databases or file systems
- **Credential Theft**: Retrieve cloud metadata or service credentials
- **Network Mapping**: Discover internal infrastructure

### Long-term Consequences
- **Lateral Movement**: Use SSRF as stepping stone for further attacks
- **Privilege Escalation**: Access administrative interfaces
- **Data Breaches**: Exfiltrate sensitive customer or business data
- **Compliance Violations**: Breach regulatory requirements

## Fix Implementation

### Secure Code Solution

```csharp
public class SecureSsrfController : ControllerBase
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<SecureSsrfController> _logger;
    
    // Whitelist of allowed domains
    private readonly HashSet<string> _allowedHosts = new()
    {
        "api.example.com",
        "trusted-partner.com",
        "public-service.org"
    };

    // Private IP ranges to block
    private readonly List<(IPAddress network, int prefixLength)> _privateRanges = new()
    {
        (IPAddress.Parse("10.0.0.0"), 8),
        (IPAddress.Parse("172.16.0.0"), 12),
        (IPAddress.Parse("192.168.0.0"), 16),
        (IPAddress.Parse("127.0.0.0"), 8),
        (IPAddress.Parse("169.254.0.0"), 16), // Link-local
        (IPAddress.Parse("::1"), 128), // IPv6 localhost
        (IPAddress.Parse("fc00::"), 7) // IPv6 private
    };

    [HttpGet("secure")]
    public async Task<IActionResult> SecureRequest(string url)
    {
        // Step 1: Input validation
        if (string.IsNullOrWhiteSpace(url))
            return BadRequest("URL parameter is required");

        // Step 2: URL parsing and validation
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return BadRequest("Invalid URL format");

        // Step 3: Protocol validation
        if (uri.Scheme != "http" && uri.Scheme != "https")
            return BadRequest("Only HTTP and HTTPS protocols are allowed");

        // Step 4: Host validation
        if (!IsHostAllowed(uri.Host))
            return BadRequest("Host not allowed");

        // Step 5: IP address validation
        if (!IsIpAddressAllowed(uri.Host))
            return BadRequest("IP address not allowed");

        try
        {
            // Step 6: Configure secure HTTP client
            using var secureClient = CreateSecureHttpClient();
            
            // Step 7: Make request with timeout
            var response = await secureClient.GetStringAsync(uri);
            
            // Step 8: Return sanitized response
            return Ok(new 
            { 
                message = "Request successful",
                url = uri.ToString(),
                contentLength = response.Length
                // Note: Not returning full content to prevent data exfiltration
            });
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning("HTTP request failed for URL {Url}: {Error}", uri, ex.Message);
            return BadRequest("Request failed");
        }
        catch (TaskCanceledException)
        {
            return BadRequest("Request timeout");
        }
    }

    private bool IsHostAllowed(string host)
    {
        // Check against whitelist
        return _allowedHosts.Contains(host.ToLowerInvariant());
    }

    private bool IsIpAddressAllowed(string host)
    {
        // Try to resolve hostname to IP
        if (!IPAddress.TryParse(host, out var ipAddress))
        {
            try
            {
                var hostEntry = Dns.GetHostEntry(host);
                ipAddress = hostEntry.AddressList.FirstOrDefault();
            }
            catch
            {
                return false; // Can't resolve, block it
            }
        }

        if (ipAddress == null)
            return false;

        // Check if IP is in private ranges
        foreach (var (network, prefixLength) in _privateRanges)
        {
            if (IsInSubnet(ipAddress, network, prefixLength))
                return false;
        }

        return true;
    }

    private bool IsInSubnet(IPAddress address, IPAddress network, int prefixLength)
    {
        var addressBytes = address.GetAddressBytes();
        var networkBytes = network.GetAddressBytes();

        if (addressBytes.Length != networkBytes.Length)
            return false;

        var bytesToCheck = prefixLength / 8;
        var bitsToCheck = prefixLength % 8;

        // Check full bytes
        for (int i = 0; i < bytesToCheck; i++)
        {
            if (addressBytes[i] != networkBytes[i])
                return false;
        }

        // Check remaining bits
        if (bitsToCheck > 0)
        {
            var mask = (byte)(0xFF << (8 - bitsToCheck));
            return (addressBytes[bytesToCheck] & mask) == (networkBytes[bytesToCheck] & mask);
        }

        return true;
    }

    private HttpClient CreateSecureHttpClient()
    {
        var client = new HttpClient();
        
        // Set reasonable timeout
        client.Timeout = TimeSpan.FromSeconds(10);
        
        // Set user agent
        client.DefaultRequestHeaders.Add("User-Agent", "SecureApplication/1.0");
        
        // Limit response size
        client.MaxResponseContentBufferSize = 1024 * 1024; // 1MB max
        
        return client;
    }
}
```

## How the Fix Works

### 1. Input Validation
```csharp
if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
    return BadRequest("Invalid URL format");
```
- **Problem Solved**: Prevents malformed URLs that could bypass filters
- **How**: Uses .NET's URI parser to validate URL structure

### 2. Protocol Restriction
```csharp
if (uri.Scheme != "http" && uri.Scheme != "https")
    return BadRequest("Only HTTP and HTTPS protocols are allowed");
```
- **Problem Solved**: Prevents file://, ftp://, gopher:// protocol exploitation
- **How**: Explicitly whitelists only HTTP/HTTPS schemes

### 3. Host Whitelisting
```csharp
private readonly HashSet<string> _allowedHosts = new()
{
    "api.example.com",
    "trusted-partner.com"
};
```
- **Problem Solved**: Only allows requests to pre-approved destinations
- **How**: Maintains a whitelist of trusted domains

### 4. IP Address Validation
```csharp
private bool IsIpAddressAllowed(string host)
{
    // Resolve hostname and check against private IP ranges
}
```
- **Problem Solved**: Prevents access to internal networks and localhost
- **How**: 
  - Resolves hostnames to IP addresses
  - Checks against private IP ranges (RFC 1918)
  - Blocks loopback and link-local addresses

### 5. Network Range Blocking
```csharp
private readonly List<(IPAddress network, int prefixLength)> _privateRanges = new()
{
    (IPAddress.Parse("10.0.0.0"), 8),        // 10.0.0.0/8
    (IPAddress.Parse("172.16.0.0"), 12),     // 172.16.0.0/12
    (IPAddress.Parse("192.168.0.0"), 16),    // 192.168.0.0/16
    (IPAddress.Parse("127.0.0.0"), 8),       // 127.0.0.0/8 (localhost)
    (IPAddress.Parse("169.254.0.0"), 16)     // 169.254.0.0/16 (link-local)
};
```
- **Problem Solved**: Blocks all private network ranges comprehensively
- **How**: Uses CIDR notation to define blocked network ranges

### 6. DNS Rebinding Protection
```csharp
// Resolve hostname to IP and validate
var hostEntry = Dns.GetHostEntry(host);
ipAddress = hostEntry.AddressList.FirstOrDefault();
```
- **Problem Solved**: Prevents DNS rebinding attacks
- **How**: Resolves the hostname and validates the actual IP address

### 7. Request Limitations
```csharp
client.Timeout = TimeSpan.FromSeconds(10);
client.MaxResponseContentBufferSize = 1024 * 1024; // 1MB max
```
- **Problem Solved**: Prevents resource exhaustion and long-running requests
- **How**: Sets strict timeouts and response size limits

### 8. Response Sanitization
```csharp
return Ok(new 
{ 
    message = "Request successful",
    url = uri.ToString(),
    contentLength = response.Length
    // Note: Not returning full content
});
```
- **Problem Solved**: Prevents sensitive data exfiltration
- **How**: Returns minimal information instead of full response content

## Additional Security Considerations

### Network-Level Protections
- Implement egress filtering at firewall level
- Use separate network segments for web servers
- Monitor outbound connections for anomalies

### Application-Level Monitoring
```csharp
_logger.LogWarning("SSRF attempt detected: {Url} from {ClientIP}", 
    uri, HttpContext.Connection.RemoteIpAddress);
```

### Rate Limiting
```csharp
// Implement rate limiting per IP to prevent abuse
[EnableRateLimiting("SsrfPolicy")]
public async Task<IActionResult> SecureRequest(string url)
```

## Testing the Fix

### Positive Tests (Should Work)
```bash
# Allowed domain
curl "http://localhost:5000/api/ssrf/secure?url=https://api.example.com/data"
```

### Negative Tests (Should Fail)
```bash
# Internal IP
curl "http://localhost:5000/api/ssrf/secure?url=http://192.168.1.1"

# Localhost
curl "http://localhost:5000/api/ssrf/secure?url=http://localhost:8080"

# Cloud metadata
curl "http://localhost:5000/api/ssrf/secure?url=http://169.254.169.254/latest/meta-data/"

# File protocol
curl "http://localhost:5000/api/ssrf/secure?url=file:///etc/passwd"
```

All negative tests should return appropriate error messages, demonstrating that the SSRF vulnerability has been effectively mitigated.
