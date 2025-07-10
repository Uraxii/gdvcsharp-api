# Hard Coded Secrets - Deep Dive

## What are Hard Coded Secrets?

Hard coded secrets are sensitive credentials, API keys, passwords, or cryptographic keys that are embedded directly in source code instead of being stored securely in configuration systems or environment variables. This creates a significant security risk as anyone with access to the code can view these secrets.

## Root Cause Analysis

### Why Hard Coding Secrets is Dangerous

1. **Source Code Exposure**: Anyone with code access can see the secrets
2. **Version Control History**: Secrets remain in Git history even if removed later
3. **No Rotation**: Hard-coded secrets are difficult to change without code deployment
4. **Environment Coupling**: Same secrets used across all environments
5. **Audit Trail**: No logging of secret access or rotation

### Vulnerable Code Patterns

#### 1. Direct Secret Declaration

```csharp
public class HardcodedSecretsController : ControllerBase
{
    // VULNERABILITY: Hard Coded Secrets - Never do this!
    private const string SECRET_API_KEY = "sk-1234567890abcdef";
    private const string DATABASE_PASSWORD = "P@ssw0rd123!";
    private const string JWT_SECRET = "MyVerySecretJWTKey2024!";
    private const string STRIPE_SECRET_KEY = "sk_test_51234567890abcdef";
    private const string AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    private const string AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
}
```

**Why This is Critical:**
- Secrets are visible in plain text in source code
- Stored in version control with full history
- Cannot be changed without code redeployment
- Same secrets across all environments

#### 2. Secrets in Configuration Endpoints

```csharp
[HttpGet("config/vuln")]
public IActionResult GetConfigurationVulnerable()
{
    return Ok(new
    {
        database = new
        {
            password = DATABASE_PASSWORD, // VULNERABLE: Exposing password
            connectionString = $"Server=localhost;Database=myapp;User Id=admin;Password={DATABASE_PASSWORD};"
        },
        jwt = new
        {
            secret = JWT_SECRET, // VULNERABLE: Exposing JWT secret
        },
        external = new
        {
            apiKey = SECRET_API_KEY, // VULNERABLE: Exposing API key
            stripeKey = STRIPE_SECRET_KEY, // VULNERABLE: Payment secret
            awsCredentials = new
            {
                accessKey = AWS_ACCESS_KEY, // VULNERABLE: Cloud credentials
                secretKey = AWS_SECRET_KEY
            }
        }
    });
}
```

**Additional Problems:**
- API endpoint exposes all secrets to anyone who can call it
- No authentication required to view sensitive configuration
- Secrets transmitted over network in plain text

#### 3. Secrets in Backup Files

```csharp
[HttpGet("backup/vuln")]
public IActionResult GetBackupVulnerable(string backupName)
{
    var backupContent = backupName switch
    {
        "config_backup.json" => $$"""
            {
                "database_password": "{{DATABASE_PASSWORD}}",
                "api_key": "{{SECRET_API_KEY}}",
                "jwt_secret": "{{JWT_SECRET}}"
            }
            """,
        "secrets_backup.txt" => $"""
            DATABASE_PASSWORD={DATABASE_PASSWORD}
            JWT_SECRET={JWT_SECRET}
            API_KEY={SECRET_API_KEY}
            """,
        // More backup files...
    };

    return Ok(new { filename = backupName, content = backupContent });
}
```

**Why This is Extremely Dangerous:**
- Backup files often contain concentrated collections of secrets
- Usually accessible without authentication
- May be forgotten and left exposed
- Often contain secrets from multiple systems

#### 4. Debug Information Exposure

```csharp
[HttpGet("debug/vuln")]
public IActionResult GetDebugInfoVulnerable()
{
    return Ok(new
    {
        configuration = new
        {
            databaseConnection = $"Server=localhost;Password={DATABASE_PASSWORD};",
            jwtSecret = JWT_SECRET,
            apiKeys = new
            {
                external = SECRET_API_KEY,
                stripe = STRIPE_SECRET_KEY
            }
        },
        internalState = new
        {
            lastDbQuery = $"SELECT * FROM users WHERE password = '{DATABASE_PASSWORD}'",
            currentJwtToken = $"Bearer {JWT_SECRET}"
        }
    });
}
```

## How Secret Exposure Attacks Work

### Discovery Methods

#### 1. Direct API Endpoint Access
```bash
# Access configuration endpoint
curl "http://localhost:5000/api/hardcodedsecrets/config/vuln"
```

**Response reveals all secrets:**
```json
{
  "database": {
    "password": "P@ssw0rd123!",
    "connectionString": "Server=localhost;Database=myapp;User Id=admin;Password=P@ssw0rd123!;"
  },
  "jwt": {
    "secret": "MyVerySecretJWTKey2024!"
  },
  "external": {
    "apiKey": "sk-1234567890abcdef",
    "stripeKey": "sk_test_51234567890abcdef",
    "awsCredentials": {
      "accessKey": "AKIAIOSFODNN7EXAMPLE",
      "secretKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
  }
}
```

#### 2. Environment Variable Enumeration
```bash
# Access environment endpoint
curl "http://localhost:5000/api/hardcodedsecrets/env/vuln"
```

**Exposes system environment:**
```json
{
  "environmentVariables": {
    "DATABASE_PASSWORD": "P@ssw0rd123!",
    "JWT_SECRET": "MyVerySecretJWTKey2024!",
    "STRIPE_SECRET_KEY": "sk_test_51234567890abcdef",
    "PATH": "/usr/local/bin:/usr/bin",
    "HOME": "/home/user"
  },
  "systemInfo": {
    "machineName": "web-server-01",
    "userName": "appuser",
    "workingDirectory": "/app"
  }
}
```

#### 3. Backup File Enumeration
```bash
# List available backups
curl "http://localhost:5000/api/hardcodedsecrets/backup/vuln"

# Access specific backup files
curl "http://localhost:5000/api/hardcodedsecrets/backup/vuln?backupName=secrets_backup.txt"
curl "http://localhost:5000/api/hardcodedsecrets/backup/vuln?backupName=.env.backup"
curl "http://localhost:5000/api/hardcodedsecrets/backup/vuln?backupName=config_backup.json"
```

#### 4. Source Code Access
```bash
# Access source files
curl "http://localhost:5000/api/hardcodedsecrets/source/vuln?file=appsettings.json"
curl "http://localhost:5000/api/hardcodedsecrets/source/vuln?file=.env"
curl "http://localhost:5000/api/hardcodedsecrets/source/vuln?file=docker-compose.yml"
```

### Attack Progression

#### Phase 1: Discovery
1. Scan for configuration endpoints (`/config`, `/debug`, `/info`)
2. Look for backup or source code endpoints
3. Check for environment variable exposure
4. Search for debug information

#### Phase 2: Secret Extraction
```bash
# Automated secret extraction
curl -s "http://localhost:5000/api/hardcodedsecrets/config/vuln" | \
  jq -r '.database.password, .jwt.secret, .external.apiKey'
```

#### Phase 3: Secret Utilization
```bash
# Use extracted database credentials
mysql -h localhost -u admin -p'P@ssw0rd123!' myapp

# Create JWT tokens with extracted secret
python create_jwt.py --secret "MyVerySecretJWTKey2024!" --user admin

# Access external APIs with extracted keys
curl -H "Authorization: Bearer sk-1234567890abcdef" "https://api.external.com/sensitive-data"
```

#### Phase 4: Lateral Movement
```bash
# Use AWS credentials for cloud access
aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE
aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws s3 ls  # List all S3 buckets
aws ec2 describe-instances  # Enumerate EC2 instances
```

## Impact Analysis

### Immediate Consequences
- **Database Compromise**: Direct access to application databases
- **External Service Access**: Unauthorized use of third-party APIs
- **Cloud Account Takeover**: Full access to cloud infrastructure
- **Payment System Abuse**: Unauthorized transactions via payment APIs

### Long-term Impact
- **Data Breaches**: Complete customer data exposure
- **Financial Loss**: Unauthorized charges and resource usage
- **Compliance Violations**: Regulatory penalties for exposed PII
- **Reputation Damage**: Loss of customer trust

### Real-World Attack Scenarios

#### Scenario 1: Database Credential Exposure
```sql
-- Attacker gains direct database access
SELECT * FROM users WHERE role = 'admin';
SELECT credit_card_number, cvv FROM payments;
DROP TABLE audit_logs;  -- Cover tracks
```

#### Scenario 2: JWT Secret Compromise
```python
# Attacker creates admin tokens
import jwt

secret = "MyVerySecretJWTKey2024!"
payload = {
    "user": "admin",
    "role": "administrator", 
    "exp": time.time() + 86400
}

token = jwt.encode(payload, secret, algorithm="HS256")
# Use token to access admin endpoints
```

#### Scenario 3: Cloud Infrastructure Takeover
```bash
# Complete AWS account compromise
aws iam list-users
aws s3 sync s3://sensitive-data-bucket ./stolen-data/
aws ec2 run-instances --image-id ami-12345 --instance-type t3.large  # Mine cryptocurrency
aws iam create-user --user-name backdoor-user
```

## Fix Implementation

### 1. Configuration-Based Secrets Management

```csharp
public class SecureSecretsController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<SecureSecretsController> _logger;

    public SecureSecretsController(IConfiguration configuration, ILogger<SecureSecretsController> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    [HttpGet("secure-operation")]
    public IActionResult SecureOperation()
    {
        // SECURE: Get secrets from configuration, not hardcoded
        var dbPassword = _configuration["Database:Password"];
        var apiKey = _configuration["ExternalApi:Key"];
        var jwtSecret = _configuration["JWT:Secret"];
        
        // Validate configuration is complete
        if (string.IsNullOrEmpty(dbPassword) || 
            string.IsNullOrEmpty(apiKey) || 
            string.IsNullOrEmpty(jwtSecret))
        {
            _logger.LogError("Required configuration values are missing");
            return StatusCode(500, "Configuration error");
        }

        // Use secrets without exposing them
        var connectionString = $"Server={_configuration["Database:Server"]};Database={_configuration["Database:Name"]};User Id={_configuration["Database:Username"]};Password={dbPassword};";
        
        // Perform operations (example)
        // var dbResult = _dbService.Query(connectionString, "SELECT COUNT(*) FROM users");
        // var apiResult = _httpClient.GetAsync($"https://api.external.com/data?key={apiKey}");

        return Ok(new 
        { 
            message = "Operation completed securely",
            timestamp = DateTime.UtcNow
            // SECURE: Never return actual secret values
        });
    }
}
```

### 2. Secure Configuration Response

```csharp
[HttpGet("config/secure")]
public IActionResult GetConfigurationSecure()
{
    // SECURE: Only return non-sensitive configuration information
    return Ok(new
    {
        message = "Application configuration (sanitized)",
        database = new
        {
            server = _configuration["Database:Server"] ?? "localhost",
            port = _configuration.GetValue<int>("Database:Port", 5432),
            username = _configuration["Database:Username"] ?? "admin",
            // SECURE: Never expose password, only indicate if configured
            passwordConfigured = !string.IsNullOrEmpty(_configuration["Database:Password"]),
            sslEnabled = _configuration.GetValue<bool>("Database:SSL", true)
        },
        jwt = new
        {
            algorithm = "HS256",
            expiry = _configuration["JWT:ExpiryHours"] ?? "24h",
            // SECURE: Don't expose the actual secret
            secretConfigured = !string.IsNullOrEmpty(_configuration["JWT:Secret"]),
            issuer = _configuration["JWT:Issuer"]
        },
        external = new
        {
            endpoint = _configuration["External:ApiEndpoint"] ?? "https://api.external.com",
            // SECURE: Indicate if keys are configured without exposing them
            apiKeyConfigured = !string.IsNullOrEmpty(_configuration["External:ApiKey"]),
            timeout = _configuration.GetValue<int>("External:TimeoutSeconds", 30)
        },
        application = new
        {
            version = "2.0.0",
            environment = _configuration["ASPNETCORE_ENVIRONMENT"] ?? "Production",
            loggingLevel = _configuration["Logging:LogLevel:Default"] ?? "Information"
        },
        securityNote = "Sensitive configuration values are never exposed in API responses"
    });
}
```

### 3. Environment Variable Configuration

**appsettings.json:**
```json
{
  "Database": {
    "Server": "localhost",
    "Port": 5432,
    "Name": "myapp",
    "Username": "admin"
  },
  "JWT": {
    "Issuer": "MyApp",
    "Audience": "MyApp",
    "ExpiryHours": "24"
  },
  "External": {
    "ApiEndpoint": "https://api.external.com",
    "TimeoutSeconds": 30
  }
}
```

**Environment Variables (.env file or system environment):**
```bash
# Database secrets
DATABASE_PASSWORD=SecureP@ssw0rd2024!
DATABASE_CONNECTION_STRING=Server=prod-db;Database=myapp;User Id=admin;Password=${DATABASE_PASSWORD};

# JWT secrets
JWT_SECRET=VerySecureJWTSigningKey2024WithEnoughEntropy!

# External API keys
EXTERNAL_API_KEY=prod-sk-1234567890abcdef
STRIPE_SECRET_KEY=sk_live_51234567890abcdef

# Cloud credentials
AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF
AWS_SECRET_ACCESS_KEY=RealSecretKeyWithProperEntropy123456789
```

### 4. Azure Key Vault Integration

```csharp
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        var builder = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json")
            .AddEnvironmentVariables();

        // SECURE: Add Azure Key Vault if configured
        var keyVaultUrl = Environment.GetEnvironmentVariable("KEY_VAULT_URL");
        if (!string.IsNullOrEmpty(keyVaultUrl))
        {
            var credential = new DefaultAzureCredential();
            builder.AddAzureKeyVault(new Uri(keyVaultUrl), credential);
        }

        Configuration = builder.Build();
        
        services.AddSingleton<IConfiguration>(Configuration);
        services.AddControllers();
        
        // Configure services with secrets from Key Vault
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(Configuration["JWT-Secret"])), // From Key Vault
                    ValidateIssuer = true,
                    ValidIssuer = Configuration["JWT:Issuer"],
                    ValidateAudience = true,
                    ValidAudience = Configuration["JWT:Audience"]
                };
            });
    }
}
```

### 5. Secure Backup Handling

```csharp
[HttpGet("backup/secure")]
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

// SECURE: Separate, authenticated endpoint for authorized backup access
[Authorize(Roles = "SystemAdmin")]
[HttpGet("admin/backup-status")]
public IActionResult GetBackupStatus()
{
    // Only return metadata, never content
    return Ok(new
    {
        lastBackupTime = DateTime.UtcNow.AddHours(-6),
        backupSizeBytes = 1024 * 1024 * 100, // 100MB
        backupLocation = "Secure storage - path not disclosed",
        backupCount = 7,
        retentionDays = 30,
        encryptionEnabled = true,
        securityNote = "Backup content is never exposed via API"
    });
}
```

### 6. Development vs Production Configuration

**Development (appsettings.Development.json):**
```json
{
  "Database": {
    "Server": "localhost",
    "Name": "myapp_dev"
  },
  "External": {
    "ApiEndpoint": "https://api-sandbox.external.com"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Debug"
    }
  }
}
```

**Production secrets managed via:**
- Azure Key Vault
- AWS Secrets Manager
- HashiCorp Vault
- Kubernetes Secrets
- Environment variables on secure infrastructure

## How the Fixes Work

### 1. Configuration Abstraction
```csharp
var secret = _configuration["JWT:Secret"];
```
- **Problem Solved**: Removes secrets from source code
- **How**: Secrets come from external configuration sources
- **Benefit**: Different secrets per environment, rotation possible

### 2. Secret Indication Without Exposure
```csharp
secretConfigured = !string.IsNullOrEmpty(_configuration["JWT:Secret"])
```
- **Problem Solved**: Provides configuration status without exposing values
- **How**: Returns boolean indicating if secret is configured
- **Benefit**: Debugging capability without security risk

### 3. Centralized Secret Management
```csharp
builder.AddAzureKeyVault(new Uri(keyVaultUrl), credential);
```
- **Problem Solved**: Professional secret management with audit trails
- **How**: Integrates with enterprise secret management systems
- **Benefits**: Rotation, access control, audit logging, encryption at rest

### 4. Environment Separation
- **Problem Solved**: Different secrets for dev/staging/production
- **How**: Environment-specific configuration files and variables
- **Benefit**: Development doesn't use production credentials

### 5. Access Control for Sensitive Endpoints
```csharp
[Authorize(Roles = "SystemAdmin")]
```
- **Problem Solved**: Restricts access to configuration information
- **How**: Requires authentication and proper authorization
- **Benefit**: Only authorized users can view system status

## Best Practices Implementation

### 1. Secret Rotation System
```csharp
public class SecretRotationService
{
    private readonly IKeyVaultClient _keyVault;
    private readonly ILogger<SecretRotationService> _logger;

    public async Task RotateJwtSecretAsync()
    {
        // Generate new secret
        var newSecret = GenerateSecureSecret(256);
        
        // Store with versioning
        await _keyVault.SetSecretAsync("JWT-Secret", newSecret);
        
        _logger.LogInformation("JWT secret rotated successfully");
    }

    private string GenerateSecureSecret(int bitLength)
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[bitLength / 8];
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes);
    }
}
```

### 2. Configuration Validation
```csharp
public class ConfigurationValidator
{
    public static void ValidateConfiguration(IConfiguration configuration)
    {
        var requiredSecrets = new[]
        {
            "Database:Password",
            "JWT:Secret", 
            "External:ApiKey"
        };

        var missingSecrets = requiredSecrets
            .Where(key => string.IsNullOrEmpty(configuration[key]))
            .ToList();

        if (missingSecrets.Any())
        {
            throw new InvalidOperationException(
                $"Missing required configuration: {string.Join(", ", missingSecrets)}");
        }

        // Validate secret strength
        var jwtSecret = configuration["JWT:Secret"];
        if (jwtSecret.Length < 32)
        {
            throw new InvalidOperationException("JWT secret must be at least 32 characters");
        }
    }
}
```

### 3. Secure Logging
```csharp
public class SecureLogger
{
    private readonly ILogger _logger;
    private readonly string[] _sensitiveFields = { "password", "secret", "key", "token" };

    public void LogSecurely(string message, object data)
    {
        var sanitizedData = SanitizeLogData(data);
        _logger.LogInformation(message, sanitizedData);
    }

    private object SanitizeLogData(object data)
    {
        // Remove or mask sensitive fields
        var json = JsonSerializer.Serialize(data);
        var doc = JsonDocument.Parse(json);
        
        // Implementation to mask sensitive fields
        return doc; // Sanitized version
    }
}
```

## Testing the Fix

### Configuration Tests
```bash
# Should not expose secrets
curl "http://localhost:5000/api/hardcodedsecrets/config/secure"

# Should require authentication for admin endpoints
curl "http://localhost:5000/api/admin/backup-status"

# Should reject backup file access
curl "http://localhost:5000/api/hardcodedsecrets/backup/secure"
```

### Environment Variable Tests
```bash
# Verify secrets are loaded from environment
export JWT_SECRET="TestSecretForValidation123456789"
export DATABASE_PASSWORD="TestDbPassword123!"

# Application should start successfully with proper secrets
dotnet run
```

### Secret Rotation Tests
```csharp
[Test]
public async Task SecretRotation_ShouldUpdateKeyVault()
{
    var rotationService = new SecretRotationService(_keyVaultClient, _logger);
    
    var oldSecret = await _keyVaultClient.GetSecretAsync("JWT-Secret");
    await rotationService.RotateJwtSecretAsync();
    var newSecret = await _keyVaultClient.GetSecretAsync("JWT-Secret");
    
    Assert.NotEqual(oldSecret.Value, newSecret.Value);
    Assert.True(newSecret.Value.Length >= 32);
}
```

The comprehensive fix ensures that secrets are never exposed in source code, API responses, or logs, while providing proper configuration management and rotation capabilities.
