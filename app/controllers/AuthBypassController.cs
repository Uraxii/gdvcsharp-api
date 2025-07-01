using Microsoft.AspNetCore.Mvc;

namespace GDVCSharp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthBypassController : ControllerBase
    {
        private readonly ILogger<AuthBypassController> _logger;

        // VULNERABILITY: Hard Coded Secrets
        private const string SECRET_API_KEY = "sk-1234567890abcdef";
        private const string DATABASE_PASSWORD = "P@ssw0rd123!";
        private const string JWT_SECRET = "MyVerySecretJWTKey2024!";

        public AuthBypassController(ILogger<AuthBypassController> logger)
        {
            _logger = logger;
        }

        // VULNERABILITY: Authorization Bypass - Missing Return Statement
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

        // VULNERABILITY: Authorization Bypass - Role Parameter Injection
        [HttpGet("admin/dashboard")]
        public IActionResult AdminDashboard(string userId, string role = "user")
        {
            // VULNERABLE: Trusting user-supplied role parameter for authorization
            // User can simply pass role=admin to bypass authorization checks

            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("UserId parameter is required");
            }

            // VULNERABLE: No actual user verification - just checking the role parameter
            if (role.ToLower() != "admin")
            {
                return Unauthorized(new
                {
                    error = "Access denied to admin dashboard",
                    message = "Admin role required",
                    hint = "Try setting the role parameter to 'admin'"  // VULNERABLE: Giving away the bypass method
                });
            }

            // VULNERABLE: Exposing extremely sensitive admin data to anyone who passes role=admin
            return Ok(new
            {
                message = "Welcome to the Admin Dashboard",
                userId = userId,
                detectedRole = role,
                adminData = new
                {
                    totalUsers = 15623,
                    activeAdmins = new[] { "admin", "root", "administrator", "sa" },
                    recentLogins = new[] {
                        new { user = "admin", ip = "192.168.1.100", time = DateTime.UtcNow.AddMinutes(-5) },
                        new { user = "john.doe", ip = "10.0.0.15", time = DateTime.UtcNow.AddMinutes(-12) }
                    },
                    systemAlerts = new[] {
                        "Failed login attempts detected from IP 203.0.113.45",
                        "Database backup failed - storage quota exceeded",
                        "SSL certificate expires in 7 days"
                    },
                    // VULNERABLE: Database credentials and secrets exposed
                    databaseCredentials = new
                    {
                        connectionString = $"Server=db.internal;Database=ProductionDB;Username=admin;Password={DATABASE_PASSWORD}",
                        adminApiKey = SECRET_API_KEY,
                        jwtSigningKey = JWT_SECRET,
                        encryptionKey = "AES256-SuperSecret-Key-123!"
                    },
                    // VULNERABLE: Internal infrastructure details
                    infrastructure = new
                    {
                        servers = new[] { "web01.internal", "db01.internal", "cache01.internal" },
                        loadBalancer = "lb.internal:8080",
                        backupLocation = "/var/backups/sensitive/",
                        monitoringUrl = "http://monitoring.internal:3000"
                    }
                },
                systemInfo = new
                {
                    serverName = Environment.MachineName,
                    currentUser = Environment.UserName,
                    workingDirectory = Directory.GetCurrentDirectory(),
                    processorCount = Environment.ProcessorCount,
                    totalMemory = GC.GetTotalMemory(false)
                }
            });
        }

        // VULNERABILITY: Authorization Bypass - Cookie-based bypass
        [HttpGet("admin/settings")]
        public IActionResult AdminSettings()
        {
            // VULNERABLE: Using insecure cookie-based authorization
            var adminCookie = HttpContext.Request.Cookies["isAdmin"];
            var userLevel = HttpContext.Request.Cookies["userLevel"];
            var debugMode = HttpContext.Request.Cookies["debug"];

            // VULNERABLE: Simple string comparison for authorization
            if (adminCookie != "true" && userLevel != "5" && debugMode != "enabled")
            {
                return Unauthorized(new
                {
                    error = "Access denied to admin settings",
                    hint = "Try setting cookies: isAdmin=true OR userLevel=5 OR debug=enabled",
                    exampleRequest = "curl -H \"Cookie: isAdmin=true\" http://localhost:5000/api/authbypass/admin/settings"
                });
            }

            return Ok(new
            {
                message = "Admin settings access granted",
                accessGrantedVia = new
                {
                    isAdminCookie = adminCookie == "true",
                    userLevelCookie = userLevel == "5",
                    debugCookie = debugMode == "enabled"
                },
                settings = new
                {
                    databaseUrl = $"mongodb://admin:{DATABASE_PASSWORD}@localhost:27017",
                    apiKeys = new
                    {
                        stripe = SECRET_API_KEY,
                        jwt = JWT_SECRET,
                        aws = "AKIA1234567890ABCDEF"
                    },
                    featureFlags = new
                    {
                        enableDebugMode = true,
                        bypassSecurity = true,
                        logPasswords = true
                    }
                }
            });
        }

        // VULNERABILITY: Authorization Bypass - HTTP Method Override
        [HttpGet("admin/delete-user/{userId}")]
        [HttpPost("admin/delete-user/{userId}")]
        [HttpDelete("admin/delete-user/{userId}")]
        public IActionResult DeleteUser(string userId)
        {
            // VULNERABLE: Dangerous operation available via GET request
            // Also bypasses authorization entirely

            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("UserId is required");
            }

            // VULNERABLE: No authorization check at all
            // VULNERABLE: Performing destructive action without confirmation

            var httpMethod = HttpContext.Request.Method;

            return Ok(new
            {
                message = "User deletion processed",
                deletedUserId = userId,
                httpMethod = httpMethod,
                timestamp = DateTime.UtcNow,
                supportedMethods = new[] { "GET", "POST", "DELETE" },
                warning = "This endpoint accepts any HTTP method and requires no authorization!",
                executionDetails = new
                {
                    serverTime = DateTime.UtcNow,
                    requestId = Guid.NewGuid(),
                    userAgent = HttpContext.Request.Headers["User-Agent"].FirstOrDefault(),
                    sourceIP = HttpContext.Connection.RemoteIpAddress?.ToString()
                }
            });
        }
    }

    public class UserRequest
    {
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
    }
}
