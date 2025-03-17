# Regular ExpressionDential of Service (ReDoS)

## Overview

ReDoS attacks attempt to degrade or deny access to a system by providing regex strings that result in excessive resources consumption. Practicle regulare expression (regex) patterns become complex quickly, making it can be difficult to identify when an exploitable flaw exists. These flaws are known as runaway expressions or evil regex. These expressions take an exessive ammount of time/memory to complete searches on some strings. Iterations to complete a search can be expotnetial with some inputs, so vulnerable expressions may runaway on even small inputs.

## Exploitation

A ReDos vulnerability exists in the ReDos API example endpoint.

```
localhost:5001/api/redos/vuln?phone=8185550123
```

This function attempts to find and capture a phone number using an exploitable regex pattern.

```
[HttpGet("vuln")]
public IActionResult RedosVuln(string phone)
{
    string pattern = "^(\\d+)$";

    Match match = Regex.Match(phone, pattern);

    return Ok(phone + "," + pattern + "," + match.Value + ",");
}
```

Lets break down the regex pattern.

^       = Begins matching at the start of the line.
(\\d+)  = Finds a digit followed by a digit, and stores the match in a capture group.
\+      = Find the capture group more than 1 time.
$       = Stops matching at the end of the line.

This will match as many digits \[0-9\] starting at the begining of the line as possible, and store them as a match. It them tries to find that match until the end of the line.

TO DO: Exlain the steps this regex performs to find a match.

## Impact

Degradation or outages effecting availability may occur as a result of flawed regex expressions.

## Mitigations

- Using nested qauntifiers.

`(\d+)+`

- Pairing quantifiers with groups that contain overlapping values.

`(C|C)+` or `\d+\d+`
