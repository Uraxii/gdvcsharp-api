using Microsoft.AspNetCore.Mvc;

namespace GdvCsharp.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class HardcodedSecretsController : ControllerBase
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<HardcodedSecretsController> _logger;
        private readonly IConfiguration _configuration;

        // VULNERABILITY: Hard Coded Secrets - Never do this!
        private const string SECRET_API_KEY = "sk-1234567890abcdef";
        private const string DATABASE_PASSWORD = "P@ssw0rd123!";
        private const string JWT_SECRET = "MyVerySecretJWTKey2024!";
        private const string STRIPE_SECRET_KEY = "sk_test_51234567890abcdef";
        private const string AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
        private const string AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

        public HardcodedSecretsController(ILogger<HardcodedSecretsController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
            _httpClient = new HttpClient();
        }

        // VULNERABILITY: Hard Coded Secrets Exposure in Configuration Endpoint
        [HttpGet("config/vuln")]
        public IActionResult GetConfigurationVulnerable()
        {
            return Ok(new
            {
                message = "Application configuration",
                database = new
                {
                    server = "localhost",
                    port = 5432,
                    username = "admin",
                    password = DATABASE_PASSWORD, // VULNERABLE: Exposing password
                    connectionString = $"Server=localhost;Database=myapp;User Id=admin;Password={DATABASE_PASSWORD};"
                },
                jwt = new
                {
                    secret = JWT_SECRET, // VULNERABLE: Exposing JWT secret
                    algorithm = "HS256",
                    expiry = "24h"
                },
                external = new
                {
                    apiKey = SECRET_API_KEY, // VULNERABLE: Exposing API key
                    endpoint = "https://api.external.com",
                    stripeKey = STRIPE_SECRET_KEY, // VULNERABLE: Payment secret
                    awsCredentials = new
                    {
                        accessKey = AWS_ACCESS_KEY, // VULNERABLE: Cloud credentials
                        secretKey = AWS_SECRET_KEY
                    }
                },
                @internal = new
                {
                    adminPassword = "admin123", // VULNERABLE: Admin credentials
                    backupPassword = "backup456",
                    encryptionKey = "my-secret-encryption-key-2024"
                }
            });
        }

        // SECURE: Configuration Without Secrets
        [HttpGet("config/solution")]
        public IActionResult GetConfigurationSecure()
        {
            return Ok(new
            {
                message = "Application configuration (sanitized)",
                database = new
                {
                    server = _configuration["Database:Server"] ?? "localhost",
                    port = _configuration.GetValue<int>("Database:Port", 5432),
                    username = _configuration["Database:Username"] ?? "admin",
                    // SECURE: Never expose password
                    passwordConfigured = !string.IsNullOrEmpty(_configuration["Database:Password"])
                },
                jwt = new
                {
                    // SECURE: Don't expose the actual secret
                    algorithm = "HS256",
                    expiry = _configuration["JWT:ExpiryHours"] ?? "24h",
                    secretConfigured = !string.IsNullOrEmpty(_configuration["JWT:Secret"])
                },
                external = new
                {
                    endpoint = _configuration["External:ApiEndpoint"] ?? "https://api.external.com",
                    // SECURE: Indicate if keys are configured without exposing them
                    apiKeyConfigured = !string.IsNullOrEmpty(_configuration["External:ApiKey"]),
                    stripeConfigured = !string.IsNullOrEmpty(_configuration["Stripe:SecretKey"])
                },
                securityNote = "Sensitive configuration values are not exposed in API responses"
            });
        }

        // VULNERABILITY: Secrets in GET Request Parameters
        [HttpGet("auth/vuln")]
        public IActionResult AuthenticateVulnerable(string username, string password, string apiKey)
        {
            // VULNERABLE: Secrets in GET parameters are logged everywhere
            _logger.LogInformation($"Authentication attempt - User: {username}, Password: {password}, ApiKey: {apiKey}");

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
            // - Browser developer tools
            // - Network monitoring tools

            var isValidCredentials = username == "admin" && password == "secret123";
            var isValidApiKey = apiKey == SECRET_API_KEY;

            if (isValidCredentials && isValidApiKey)
            {
                return Ok(new
                {
                    message = "Authentication successful",
                    token = "jwt-token-here",
                    user = username,
                    // VULNERABLE: Echoing back secrets
                    usedPassword = password,
                    usedApiKey = apiKey,
                    internalSecret = JWT_SECRET,
                    vulnerability = "Secrets exposed in GET parameters and response body"
                });
            }

            return Unauthorized(new
            {
                error = "Invalid credentials",
                // VULNERABLE: Revealing attempted credentials
                attemptedUsername = username,
                attemptedPassword = password,
                attemptedApiKey = apiKey,
                hint = "This response leaks the attempted credentials"
            });
        }

        // SECURE: Authentication with POST and No Secret Exposure
        [HttpPost("auth/solution")]
        public IActionResult AuthenticateSecure([FromBody] LoginRequest request)
        {
            if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest("Username and password are required");
            }

            // SECURE: Log without sensitive data
            _logger.LogInformation("Authentication attempt for user: {username}", request.Username);

            // SECURE: Get credentials from configuration
            var validUsername = _configuration["Auth:Username"];
            var validPassword = _configuration["Auth:Password"];
            var validApiKey = _configuration["Auth:ApiKey"];

            var isValidCredentials = request.Username == validUsername && request.Password == validPassword;
            var isValidApiKey = request.ApiKey == validApiKey;

            if (isValidCredentials && isValidApiKey)
            {
                return Ok(new
                {
                    message = "Authentication successful",
                    token = "jwt-token-here",
                    user = request.Username,
                    // SECURE: No sensitive data in response
                    securityNote = "Credentials validated securely without exposure"
                });
            }

            // SECURE: Generic error message
            return Unauthorized(new
            {
                error = "Invalid credentials",
                securityNote = "No credential details revealed in error response"
            });
        }

        // VULNERABILITY: Environment Variables and System Info Exposure
        [HttpGet("env/vuln")]
        public IActionResult GetEnvironmentVulnerable()
        {
            // VULNERABLE: Exposing all environment variables
            var envVars = Environment.GetEnvironmentVariables()
                .Cast<System.Collections.DictionaryEntry>()
                .ToDictionary(e => e.Key.ToString(), e => e.Value?.ToString());

            return Ok(new
            {
                message = "Environment variables and system information",
                environmentVariables = envVars,
                systemInfo = new
                {
                    machineName = Environment.MachineName,
                    userName = Environment.UserName,
                    workingDirectory = Environment.CurrentDirectory,
                    processId = Environment.ProcessId,
                    commandLine = Environment.CommandLine,
                    osVersion = Environment.OSVersion.ToString(),
                    clrVersion = Environment.Version.ToString(),
                    processorCount = Environment.ProcessorCount
                },
                hardCodedSecrets = new
                {
                    // VULNERABLE: Exposing hardcoded secrets
                    databasePassword = DATABASE_PASSWORD,
                    jwtSecret = JWT_SECRET,
                    apiKey = SECRET_API_KEY,
                    stripeKey = STRIPE_SECRET_KEY
                },
                vulnerability = "Complete system information and secrets exposure"
            });
        }

        // SECURE: Limited System Information
        [HttpGet("env/solution")]
        public IActionResult GetEnvironmentSecure()
        {
            // SECURE: Only expose non-sensitive system information
            return Ok(new
            {
                message = "System information (sanitized)",
                systemInfo = new
                {
                    applicationName = "GDVCSharp API",
                    version = "1.0.0",
                    environment = _configuration["ASPNETCORE_ENVIRONMENT"] ?? "Production",
                    dotnetVersion = Environment.Version.ToString(),
                    // SECURE: No sensitive system details
                    isProduction = !Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")?.Equals("Development", StringComparison.OrdinalIgnoreCase) ?? true
                },
                securityNote = "Only non-sensitive system information is exposed"
            });
        }

        // VULNERABILITY: Backup Files with Secrets
        [HttpGet("backup/vuln")]
        public IActionResult GetBackupVulnerable(string backupName)
        {
            if (string.IsNullOrEmpty(backupName))
            {
                // VULNERABLE: Listing available backup files
                return Ok(new
                {
                    message = "Available backup files",
                    files = new[]
                    {
                        "users_backup_2024.sql",
                        "config_backup.json",
                        "secrets_backup.txt",
                        "database_dump.sql",
                        ".env.backup",
                        "app_settings.backup",
                        "keys_backup.json"
                    },
                    hint = "Add ?backupName=filename to download specific backup",
                    vulnerability = "Backup files often contain sensitive information"
                });
            }

            // VULNERABLE: No access control and secrets in backup files
            var backupContent = backupName switch
            {
                "config_backup.json" => $$"""
                        {
                            "database_password": "{{DATABASE_PASSWORD}}",
                            "api_key": "{{SECRET_API_KEY}}",
                            "jwt_secret": "{{JWT_SECRET}}",
                            "stripe_key": "{{STRIPE_SECRET_KEY}}"
                        }
                        """,
                "secrets_backup.txt" => $"""
                        # Application Secrets Backup
                        DATABASE_PASSWORD={DATABASE_PASSWORD}
                        JWT_SECRET={JWT_SECRET}
                        API_KEY={SECRET_API_KEY}
                        STRIPE_SECRET_KEY={STRIPE_SECRET_KEY}
                        AWS_ACCESS_KEY={AWS_ACCESS_KEY}
                        AWS_SECRET_KEY={AWS_SECRET_KEY}
                        """,
                ".env.backup" => $"""
                        DB_PASSWORD={DATABASE_PASSWORD}
                        JWT_SECRET={JWT_SECRET}
                        STRIPE_KEY={STRIPE_SECRET_KEY}
                        AWS_ACCESS_KEY_ID={AWS_ACCESS_KEY}
                        AWS_SECRET_ACCESS_KEY={AWS_SECRET_KEY}
                        """,
                "users_backup_2024.sql" => """
                        CREATE TABLE users (id int, username varchar(50), password varchar(100));
                        INSERT INTO users VALUES (1, 'admin', 'plaintext_password_123');
                        INSERT INTO users VALUES (2, 'user', 'password123');
                        INSERT INTO users VALUES (3, 'test', 'test123');
                        """,
                "keys_backup.json" => $$"""
                        {
                            "encryption_keys": {
                                "primary": "{{JWT_SECRET}}",
                                "secondary": "backup-encryption-key-456"
                            },
                            "api_keys": {
                                "external": "{{SECRET_API_KEY}}",
                                "payment": "{{STRIPE_SECRET_KEY}}"
                            }
                        }
                        """,
                _ => "Backup file not found"
            };

            return Ok(new
            {
                filename = backupName,
                content = backupContent,
                warning = "This backup contains highly sensitive information!",
                vulnerability = "Backup files accessible without authentication and contain secrets"
            });
        }

        // SECURE: No Backup File Access
        [HttpGet("backup/solution")]
        public IActionResult GetBackupSecure()
        {
            // SECURE: Backup files should never be accessible via API
            return StatusCode(403, new
            {
                error = "Access denied",
                message = "Backup files are not accessible via API endpoints",
                securityNote = "Backup files should be stored securely and accessed only by authorized personnel through secure channels"
            });
        }

        // VULNERABILITY: Source Code Exposure
        [HttpGet("source/vuln")]
        public IActionResult GetSourceCodeVulnerable(string file)
        {
            if (string.IsNullOrEmpty(file))
            {
                return Ok(new
                {
                    message = "Available source files",
                    files = new[]
                    {
                        "appsettings.json",
                        "Program.cs",
                        "Startup.cs",
                        "Controllers/HardcodedSecretsController.cs",
                        ".env",
                        "docker-compose.yml"
                    },
                    hint = "Add ?file=filename to view source code"
                });
            }

            // VULNERABLE: Exposing source code with secrets
            var sourceContent = file switch
            {
                "appsettings.json" => $$"""
                        {
                            "ConnectionStrings": {
                                "DefaultConnection": "Server=localhost;Database=myapp;User Id=admin;Password={{DATABASE_PASSWORD}};"
                            },
                            "JWT": {
                                "Secret": "{{JWT_SECRET}}",
                                "Issuer": "MyApp",
                                "Audience": "MyApp"
                            },
                            "ExternalAPIs": {
                                "ApiKey": "{{SECRET_API_KEY}}",
                                "StripeKey": "{{STRIPE_SECRET_KEY}}"
                            }
                        }
                        """,
                ".env" => $"""
                        DATABASE_URL=postgresql://admin:{DATABASE_PASSWORD}@localhost:5432/myapp
                        JWT_SECRET={JWT_SECRET}
                        API_KEY={SECRET_API_KEY}
                        STRIPE_SECRET_KEY={STRIPE_SECRET_KEY}
                        AWS_ACCESS_KEY_ID={AWS_ACCESS_KEY}
                        AWS_SECRET_ACCESS_KEY={AWS_SECRET_KEY}
                        """,
                "docker-compose.yml" => $"""
                        version: '3.8'
                        services:
                          app:
                            build: .
                            environment:
                              - DATABASE_PASSWORD={DATABASE_PASSWORD}
                              - JWT_SECRET={JWT_SECRET}
                              - API_KEY={SECRET_API_KEY}
                          db:
                            image: postgres
                            environment:
                              - POSTGRES_PASSWORD={DATABASE_PASSWORD}
                        """,
                _ => "Source file not found"
            };

            return Ok(new
            {
                filename = file,
                content = sourceContent,
                vulnerability = "Source code exposure reveals hardcoded secrets and configuration"
            });
        }

        // VULNERABILITY: Debug Information with Secrets
        [HttpGet("debug/vuln")]
        public IActionResult GetDebugInfoVulnerable()
        {
            return Ok(new
            {
                message = "Debug information",
                configuration = new
                {
                    databaseConnection = $"Server=localhost;Database=myapp;User Id=admin;Password={DATABASE_PASSWORD};",
                    jwtSecret = JWT_SECRET,
                    apiKeys = new
                    {
                        external = SECRET_API_KEY,
                        stripe = STRIPE_SECRET_KEY,
                        aws = new
                        {
                            accessKey = AWS_ACCESS_KEY,
                            secretKey = AWS_SECRET_KEY
                        }
                    }
                },
                internalState = new
                {
                    lastDbQuery = $"SELECT * FROM users WHERE password = '{DATABASE_PASSWORD}'",
                    currentJwtToken = $"Bearer {JWT_SECRET}",
                    apiCallHistory = new[]
                    {
                        $"GET /api/external?key={SECRET_API_KEY}",
                        $"POST /api/payment Authorization: Bearer {STRIPE_SECRET_KEY}"
                    }
                },
                vulnerability = "Debug endpoints should never expose secrets or internal state"
            });
        }
    }

    public class LoginRequest
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string ApiKey { get; set; } = string.Empty;
    }
}
