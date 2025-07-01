using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add CORS policy (VULNERABLE: Too permissive)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// Add HttpClient
builder.Services.AddHttpClient();

// VULNERABLE: Weak JWT configuration
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,    // VULNERABLE: Not validating issuer
            ValidateAudience = false,  // VULNERABLE: Not validating audience
            ValidateLifetime = false,  // VULNERABLE: Not validating expiration
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes("MyVerySecretJWTKey2024!")) // VULNERABLE: Hardcoded key
        };
    });

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// VULNERABLE: Permissive CORS
app.UseCors("AllowAll");

app.UseAuthentication();
app.UseAuthorization();

// Create uploads directory if it doesn't exist
var uploadsPath = Path.Combine(Directory.GetCurrentDirectory(), "uploads");
if (!Directory.Exists(uploadsPath))
{
    Directory.CreateDirectory(uploadsPath);

    // Create some sample files for demonstration
    File.WriteAllText(Path.Combine(uploadsPath, "sample.txt"), "This is a sample file.");
    File.WriteAllText(Path.Combine(uploadsPath, "config.json"),
        """{"database": {"password": "secret123"}}""");
}

app.MapControllers();

// Add a simple endpoint to show the app is running
app.MapGet("/", () => Results.Json(new
{
    message = "GDVCSharp Vulnerable Web API is running",
    version = "2.0",
    swagger = "/swagger",
    vulnerabilities = new[] {
        new {
            name = "Server-Side Request Forgery (SSRF)",
            endpoint = "GET /api/ssrf/vulnerable?url={url}",
            testCommand = "curl \"http://localhost:5000/api/ssrf/vulnerable?url=http://target-server:80\"",
            description = "Allows making requests to internal services and external URLs without validation"
        },
        new {
            name = "SSRF with POST",
            endpoint = "POST /api/ssrf/post-vulnerable",
            testCommand = "curl -X POST \"http://localhost:5000/api/ssrf/post-vulnerable\" -H \"Content-Type: application/json\" -d '{\"url\": \"http://internal-service:8080/admin\", \"data\": \"test\"}'",
            description = "POST-based SSRF vulnerability"
        },
        new {
            name = "Authorization Bypass - Missing Return",
            endpoint = "POST /api/authbypass/admin/users",
            testCommand = "curl -X POST \"http://localhost:5000/api/authbypass/admin/users\" -H \"Content-Type: application/json\" -H \"X-User-Role: guest\" -d '{\"username\": \"hacker\", \"email\": \"test@test.com\"}'",
            description = "Authorization check continues execution after unauthorized access"
        },
        new {
            name = "Authorization Bypass - Role Parameter",
            endpoint = "GET /api/authbypass/admin/dashboard?userId=123&role=admin",
            testCommand = "curl \"http://localhost:5000/api/authbypass/admin/dashboard?userId=123&role=admin\"",
            description = "Admin access granted by passing role parameter"
        },
        new {
            name = "Authorization Bypass - Cookie Based",
            endpoint = "GET /api/authbypass/admin/settings",
            testCommand = "curl -H \"Cookie: isAdmin=true\" \"http://localhost:5000/api/authbypass/admin/settings\"",
            description = "Admin access via cookie manipulation"
        },
        new {
            name = "Authorization Bypass - HTTP Method Override",
            endpoint = "GET /api/authbypass/admin/delete-user/123",
            testCommand = "curl \"http://localhost:5000/api/authbypass/admin/delete-user/123\"",
            description = "Dangerous operations accessible via GET without authorization"
        },
        new {
            name = "Regular Expression Denial of Service (ReDoS)",
            endpoint = "GET /api/regex/validate?input={input}",
            testCommand = "curl \"http://localhost:5000/api/regex/validate?input=aaaaaaaaaaaaaaaaaaaaac\"",
            description = "Catastrophic backtracking in regex patterns"
        },
        new {
            name = "Regular Expression Injection",
            endpoint = "GET /api/regex/search?pattern={pattern}&text={text}",
            testCommand = "curl \"http://localhost:5000/api/regex/search?pattern=.*&text=test\"",
            description = "User-controlled regex patterns allow injection attacks"
        },
        new {
            name = "Enhanced ReDoS with Custom Patterns",
            endpoint = "GET /api/regex/validate-enhanced?input={input}&customPattern={pattern}",
            testCommand = "curl \"http://localhost:5000/api/regex/validate-enhanced?input=aaaaaaaaaaaac&customPattern=%5E%28a%2B%29%2Bb%24\"",
            description = "Multiple ReDoS patterns with user-provided custom patterns"
        },
        new {
            name = "Multi-Regex ReDoS",
            endpoint = "GET /api/regex/multi-validate?email={email}&phone={phone}&ssn={ssn}",
            testCommand = "curl \"http://localhost:5000/api/regex/multi-validate?email=test@test.com&phone=555-555-5555&ssn=123-45-6789\"",
            description = "Multiple regex validations prone to ReDoS"
        },
        new {
            name = "Cross-Site Scripting (XSS) - Reflected",
            endpoint = "GET /api/xss/search?query={query}",
            testCommand = "curl \"http://localhost:5000/api/xss/search?query=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E\"",
            description = "User input reflected in HTML without encoding"
        },
        new {
            name = "XSS in JSON Profile",
            endpoint = "GET /api/xss/profile?username={username}&bio={bio}",
            testCommand = "curl \"http://localhost:5000/api/xss/profile?username=%3Cscript%3Ealert(1)%3C/script%3E&bio=test\"",
            description = "XSS in JSON responses that get rendered client-side"
        },
        new {
            name = "XSS in Feedback Form",
            endpoint = "GET /api/xss/feedback?message={message}&category={category}",
            testCommand = "curl \"http://localhost:5000/api/xss/feedback?message=%3Cscript%3Ealert(1)%3C/script%3E&category=test\"",
            description = "XSS in feedback forms and error messages"
        },
        new {
            name = "DOM-based XSS Setup",
            endpoint = "GET /api/xss/dashboard?theme={theme}",
            testCommand = "curl \"http://localhost:5000/api/xss/dashboard?theme=light\"",
            description = "Client-side DOM manipulation vulnerabilities"
        },
        new {
            name = "XSS in Comments",
            endpoint = "POST /api/xss/comment",
            testCommand = "curl -X POST \"http://localhost:5000/api/xss/comment\" -H \"Content-Type: application/json\" -d '{\"content\": \"<script>alert(1)</script>\", \"author\": \"test\"}'",
            description = "XSS in comment posting and error handling"
        },
        new {
            name = "Hard Coded Secrets - Configuration",
            endpoint = "GET /api/hardcodedsecrets/config/vuln",
            testCommand = "curl \"http://localhost:5000/api/hardcodedsecrets/config/vuln\"",
            description = "Hardcoded secrets exposed in configuration endpoints"
        },
        new {
            name = "Secrets in GET Parameters",
            endpoint = "GET /api/hardcodedsecrets/auth/vuln?username={user}&password={pass}&apiKey={key}",
            testCommand = "curl \"http://localhost:5000/api/hardcodedsecrets/auth/vuln?username=admin&password=secret123&apiKey=sk-1234567890abcdef\"",
            description = "Sensitive data passed in GET request parameters"
        },
        new {
            name = "Environment Variable Exposure",
            endpoint = "GET /api/hardcodedsecrets/env/vuln",
            testCommand = "curl \"http://localhost:5000/api/hardcodedsecrets/env/vuln\"",
            description = "All environment variables and system info exposed"
        },
        new {
            name = "Backup Files with Secrets",
            endpoint = "GET /api/hardcodedsecrets/backup/vuln?backupName={filename}",
            testCommand = "curl \"http://localhost:5000/api/hardcodedsecrets/backup/vuln?backupName=config_backup.json\"",
            description = "Backup files containing sensitive information"
        },
        new {
            name = "Source Code Exposure",
            endpoint = "GET /api/hardcodedsecrets/source/vuln?file={filename}",
            testCommand = "curl \"http://localhost:5000/api/hardcodedsecrets/source/vuln?file=appsettings.json\"",
            description = "Source code and configuration files exposed"
        },
        new {
            name = "Debug Information with Secrets",
            endpoint = "GET /api/hardcodedsecrets/debug/vuln",
            testCommand = "curl \"http://localhost:5000/api/hardcodedsecrets/debug/vuln\"",
            description = "Debug endpoints exposing internal state and secrets"
        },
        new {
            name = "Path Traversal - File Access",
            endpoint = "GET /api/pathtraversal/vuln?filename={filename}",
            testCommand = "curl \"http://localhost:5000/api/pathtraversal/vuln?filename=../../../etc/passwd\"",
            description = "Directory traversal allows access to any file on the system"
        },
        new {
            name = "Path Traversal - Directory Listing",
            endpoint = "GET /api/pathtraversal/list/vuln?directory={directory}",
            testCommand = "curl \"http://localhost:5000/api/pathtraversal/list/vuln?directory=../../\"",
            description = "Directory listing exposes file system structure"
        },
        new {
            name = "Path Traversal - File Upload",
            endpoint = "POST /api/pathtraversal/upload/vuln",
            testCommand = "curl -X POST -F \"file=@test.txt\" -F \"directory=../../../tmp\" \"http://localhost:5000/api/pathtraversal/upload/vuln\"",
            description = "File upload with directory traversal"
        }
    },
    secureEndpoints = new
    {
        hardcodedSecrets = new
        {
            secureConfig = "GET /api/hardcodedsecrets/config/solution",
            secureAuth = "POST /api/hardcodedsecrets/auth/solution",
            secureEnv = "GET /api/hardcodedsecrets/env/solution",
            secureBackup = "GET /api/hardcodedsecrets/backup/solution"
        },
        pathTraversal = new
        {
            secureFileAccess = "GET /api/pathtraversal/solution?filename={filename}",
            secureDirectoryListing = "GET /api/pathtraversal/list/solution",
            secureFileUpload = "POST /api/pathtraversal/upload/solution"
        }
    },
    totalVulnerableEndpoints = 23,

    warning = "⚠️ This is a deliberately vulnerable application for educational purposes only!",
    disclaimer = "NEVER deploy this application in production or expose it to untrusted networks!",
    note = "All endpoints are accessible without authentication. Use /swagger for interactive API documentation."
}));

app.Run();
