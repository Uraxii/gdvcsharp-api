
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
    vulnerabilities = new[] {
        new {
            name = "Server-Side Request Forgery (SSRF)",
            endpoint = "GET /api/vulnerable/ssrf?url={url}",
            testCommand = "curl \"http://localhost:5000/api/vulnerable/ssrf?url=http://target-server:80\""
        },
        new {
            name = "Authorization Bypass",
            endpoint = "POST /api/vulnerable/admin/users",
            testCommand = "curl -X POST \"http://localhost:5000/api/vulnerable/admin/users\" -H \"Content-Type: application/json\" -H \"X-User-Role: guest\" -d '{\"username\": \"hacker\", \"email\": \"test@test.com\"}'"
        },
        new {
            name = "Regular Expression Denial of Service (ReDoS) - Basic",
            endpoint = "GET /api/vulnerable/validate?input={input}",
            testCommand = "curl \"http://localhost:5000/api/vulnerable/validate?input=aaaaaaaaaaaaaaaaaaaaac\""
        },
        new {
            name = "Regular Expression Denial of Service (ReDoS) - Enhanced",
            endpoint = "GET /api/vulnerable/regex-validate?input={input}&customPattern={pattern}",
            testCommand = "curl \"http://localhost:5000/api/vulnerable/regex-validate?input=aaaaaaaaaaaac&customPattern=%5E%28a%2B%29%2Bb%24\""
        },
        new {
            name = "Regular Expression Injection",
            endpoint = "GET /api/vulnerable/regex-search?pattern={pattern}&text={text}",
            testCommand = "curl \"http://localhost:5000/api/vulnerable/regex-search?pattern=.*&text=test\""
        },
        new {
            name = "Cross-Site Scripting (XSS)",
            endpoint = "GET /api/vulnerable/search?query={query}",
            testCommand = "curl \"http://localhost:5000/api/vulnerable/search?query=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E\""
        },
        new {
            name = "Hard Coded Secrets",
            endpoint = "GET /api/vulnerable/config",
            testCommand = "curl \"http://localhost:5000/api/vulnerable/config\""
        },
        new {
            name = "Secrets in GET Request Parameters",
            endpoint = "GET /api/vulnerable/auth?username={user}&password={pass}&apiKey={key}",
            testCommand = "curl \"http://localhost:5000/api/vulnerable/auth?username=admin&password=secret123&apiKey=sk-1234567890abcdef\""
        },
        new {
            name = "Path Traversal",
            endpoint = "GET /api/vulnerable/files?filename={filename}",
            testCommand = "curl \"http://localhost:5000/api/vulnerable/files?filename=../../../etc/passwd\""
        }
    },
    additionalEndpoints = new
    {
        multiRegexReDoS = new
        {
            endpoint = "GET /api/vulnerable/multi-regex?email={email}&phone={phone}&ssn={ssn}",
            testCommand = "curl \"http://localhost:5000/api/vulnerable/multi-regex?email=test@test.com&phone=555-555-5555&ssn=123-45-6789\""
        },
        multiVulnerability = new
        {
            endpoint = "POST /api/vulnerable/process",
            testCommand = "curl -X POST \"http://localhost:5000/api/vulnerable/process\" -H \"Content-Type: application/json\" -d '{\"username\": \"<script>alert(1)</script>\", \"data\": \"test\", \"apiKey\": \"sk-1234567890abcdef\", \"callbackUrl\": \"http://evil.com\"}'"
        },
        documentation = new
        {
            endpoint = "GET /api/vulnerable/docs",
            description = "View full documentation in markdown format"
        },
        documentationHtml = new
        {
            endpoint = "GET /api/vulnerable/docs/html",
            description = "View full documentation in HTML format"
        }
    },
    totalEndpoints = 11,
    quickTestScript = "# Run all vulnerability tests:\ncurl \"http://localhost:5000/api/vulnerable/ssrf?url=http://target-server:80\"\ncurl -X POST \"http://localhost:5000/api/vulnerable/admin/users\" -H \"Content-Type: application/json\" -H \"X-User-Role: guest\" -d '{\"username\": \"hacker\", \"email\": \"test@test.com\"}'\ncurl \"http://localhost:5000/api/vulnerable/validate?input=aaaaaaaaaaaaaaaaaaaaac\"\ncurl \"http://localhost:5000/api/vulnerable/regex-validate?input=aaaaaaaaaaaac&customPattern=%5E%28a%2B%29%2Bb%24\"\ncurl \"http://localhost:5000/api/vulnerable/regex-search?pattern=.*&text=test\"\ncurl \"http://localhost:5000/api/vulnerable/search?query=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E\"\ncurl \"http://localhost:5000/api/vulnerable/config\"\ncurl \"http://localhost:5000/api/vulnerable/auth?username=admin&password=secret123&apiKey=sk-1234567890abcdef\"\ncurl \"http://localhost:5000/api/vulnerable/files?filename=../../../etc/passwd\"",
    warning = "⚠️ This is a deliberately vulnerable application for educational purposes only!",
    disclaimer = "NEVER deploy this application in production or expose it to untrusted networks!"
}));

app.Run();

