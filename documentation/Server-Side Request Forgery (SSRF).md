# Server-Side Request Forgery (SSRF)

## Overview

SSRF attacks are commonly used to bypass authentication controls, impacting confidentiality, and is capable of enabling remote code execution. These attacks are performed by sending a URI to an endpoint that loads, stores, or returns resources from an address without performing sufficient validation. As a result, the attacker is able to load, store, or retrieve data depending on what actions the vulnerable endpoint does.

## Explotation

There is an endpoint vulnerable to SSRF at the /api/ssrf/vuln API endpoint.

```
localhost:5001/api/ssrf/vuln?uri=http://localhost:5001/api/ssrf/users
```

This function loads data from the provided URI and returns the result.

```
[HttpGet("vuln")]
public async Task<IActionResult> GetDataVulnAsync(string uri)
{
    if (uri == "")
    {
        return BadRequest("uri parameter null!");
    }

    try
    {
        var response = await _httpClient.GetStringAsync(uri);

        return Content(response, "text/plain");
    }
    catch (Exception ex)
    {
        return BadRequest($"Error fetching data from {uri}.");
    }
}
```

This method allows the attacker to provide any address and obtain data from it. Due to a authentication logic flaw in the /api/ssrf/users endpoint on the machine, the endpoint vulnerable to SSRF allows the attacker to exfiltrate the users database.

Two mitigation techniques for this logic flaw would be to either eliminate the endpoint or verify that the requester is a logged in administrator before running the query.

```
[HttpGet("users")]
public IActionResult GetAllUsers()
{
    if (!IsLocalRequest())
    {
        return Unauthorized("Not permitted.");
    }

    List<User> users = _userService.GetAllUsers();

    return Ok(users); // Returns full user data, including sensitive fields

    // string connectionString = Environment.GetEnvironmentVariable("MONGO_CONNECTION_STRING");

    // return Ok(connectionString);
}
```

It is not uncommon that several vulnerabilities are used together to complete an attack.

## Impact

TODO: THIS

## Mitigations

**Pemit and Deny Lists**

Creating a list of permitted addressesed is know as white listing/allow listing. Explicitly defining which addresses an endpoint is allowed to communicate with is always preferable. This minimizes the likelyhood of SSRF being exploited by an attacker.

However, creating an allow list is not always possible. Therefore, the alternative is black listing/denying. Though less preferable, specifying which addresses CANNOT communicate with an endpoint is a powerful control to implement.

Organizations should consider maintaining allow/deny lists in places other than the application source code. Organizations should be able to modify these lists without needing to redeploy the services. Especially in the case of deny lists, this practice will ensure that changes can be made as needed. Certainly helpful when trying to prvent an active attack, and the rules can be used to mitigtate other forms of attack like Denial of Service. Web application firewalls and API gateways are good places to implement these rules. If your endpoint is accessible via multiple paths, consider adding these rules to all your appliances.
