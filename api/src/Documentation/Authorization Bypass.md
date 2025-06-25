# Authorization Bypass
Authorization Bypass is a vulnerability that allows an attacker to perform actions and access resources without the necessary privilege or roles.

It is assumed that the system is properly authenticating the user is who they claim to be. The failure is in correctly enforcing what the user should be allowed to do.

## Methods of Authorization Bypass
### Parameter Modification

 When authentication is verified via fixed parameters there is no guarantee an attacker can't modify this request to give themselves authorization.

Example: Let's say a client can access their cart through a get request using a userID but ownership of the ID is not verified against the authenticated user.

`GET /cart?id=<UserID>`

Any adversary can change the ID to view another user's cart.
> **Note:** This example is more specifically a subset of paramater modification called **Insecure Direct Object Reference (IDOR)**.

### Direct Page Request (Forced Browsing)

Hidden, unlinked, or restricted URLs and resources can be located by an attacker by the use of guessing, enumeration, or located indirect references.

> **Note:** Assuming they will stay hidden is poor security practice and a common example of the false belief that security through obscurity is an effective practice.

### Flawed or Inconsistent Authorization Logic (covered in example)

## Example Exploit

Every endpoint that performs an action or exposes sensitive data should include authorization checks.

With how large a programs API surface can be, manually placing authorization checks can often cause mistakes.

In the example we have a dashboard that should only be accessed by those who possess an admin role.

```csharp
[HttpPost("vuln")]
public IActionResult vuln([FromBody] LoginUser model)
{
    if (!ModelState.IsValid)
    {
        return BadRequest(ModelState);
    }

    var user = _userService.AuthenticateUser(model.Username, model.Password);

    if (user == null)
    {
        return Unauthorized("Invalid credentials.");
    }
```
The AuthenticateUser function will return the authenticated user based on their username and password.
``` csharp
    if (!user.Roles.Contains("admin"))
    {
        Unauthorized("Invalid permissions");
    }

    return Ok("Heres the Dashboard");
}
```
The attempted check to verify the user possesses an admin role doesn't have a return statement on Unauthorized causing the dashboard to be seen no matter the roles of a user. This way any user can access this sensitive data. 

## Mitigations
APIs should be developed where all actions in an endpoint require the same level of  authorization. This encourages the use of "fail fast" authorization checks. Whether thats a check at the top of the function or a built-in feature of a framework the checks will be simpler and more constant between endpoints, leading to less mistakes in implementation.

## Corrected Endpoint

Actions in the original enpoint required different authorization
 - Anyone can attempt to authenticate themselves
 - Only an admin can see the dashboard

Therefore it's necessary to split these into two different endpoints.

In these corrected endpoints, we will use an authorization attribute by creating a JWT (Json Web Token). These authoriztion attributes can be placed above functions to determine whether access is permitted before the function is ever entered.

```csharp
[HttpPost("solution")]
public IActionResult solution([FromBody] LoginUser model)
{
    if (!ModelState.IsValid)
    {
        return BadRequest(ModelState);
    }

    var user = _userService.AuthenticateUser(model.Username, model.Password);

    if (user == null)
    {
        return Unauthorized("Invalid credentials.");
    }
```
A JWT is a URL safe token format which is signed with a secret key to ensure it's integrity.
``` csharp
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtSettings:Key"]!));

    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, user.Username)
    };

    claims.AddRange(user.Roles.Select(role => new Claim(ClaimTypes.Role, role)));
```
Claims of a JWT are key-value pairs that inform about the subject of the token. The roles a user has will be placed in the token as a claim.
``` csharp
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(claims),
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = creds
    };

    var tokenHandler = new JwtSecurityTokenHandler();

    var token = tokenHandler.CreateToken(tokenDescriptor);
    
    string jwt = tokenHandler.WriteToken(token);

    var jwtToken = tokenHandler.ReadJwtToken(jwt);

    return Ok(new { token = jwt});
}
```
The token is returned in the HTTP response body. This token should be sent to protcted endpoints in the HTTP Authorization header using the Bearer scheme as shown below.
```
GET /api/authbypass/viewDashboard
...
Authorization: Bearer <JWT>
```
Authorization attributes will verify and decode the token to determine if the user has permissions to use the endpoint and return a 4XX error code if not.
``` csharp
[HttpGet("viewDashboard")]
[Authorize(Roles="admin")]
public IActionResult viewDashboard()
{
    return Ok("Heres the Dashboard");
}
```

By using JWT tokens and authorization attributes,the authorization logic is now simple while still robust and secure.


