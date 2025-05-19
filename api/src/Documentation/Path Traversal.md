# Path Traversal
Path Traversal, also known as Directory Traversal, is a vulnerability where an attacker attempts to access parts of a file system outside of their intended scope.

Attackers can use path traversal to access resources such as
- Source code
- Sensitive OS files
- Config files

## Methods of Path Traversal
- Using "../" or some encoded version of it to traverse up the directory and expand scope of access

``` zsh
user@example:~$ curl https://LittleCeasars.example/public/%2e%2e/%2e%2e/etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
```
- Using a previously created symbolic link to access a sensitive file
``` zsh
// "ln -s /etc/passwd img1.jpg" previously run
user@example:~$ curl https://LittleCeasars.example/public/img1.jpg

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
```
- Using absolute path to access anything starting from the root directory (covered in example)

## Example Exploit
Our example endpoint takes in a query filename to determine which pizza's nutritional information from the "static/files/nutrition" directory should be returned.

 
```csharp
public IActionResult PathTraversalVuln(string filename)
{

    if (string.IsNullOrWhiteSpace(filename) || filename.Contains(".."))
    {
        return BadRequest("Invalid Filename.");
    }
```
An attempt to restrict path traversal is made by filtering out attemps to move up directories.
```csharp 
    string baseDir = "static/files/nutrition";

    string path = Path.Combine(Directory.GetCurrentDirectory(), baseDir, filename);
```
This is the endpoints main security flaw. In Path.Combine, if a later variable is an absolute path, all previous segments are discarded and the resulting path is the absolute path plus any remaining segments:  
`Path.Combine("root", "tmp/info.txt") -> /root/tmp/info.txt `  
`Path.Combine("root", "/tmp/info.txt") -> /tmp/info.txt  `

```csharp
    if (!System.IO.File.Exists(path))
    {
        return NotFound("File not found.");
    }

    try
    {
        string contents = System.IO.File.ReadAllText(path);

        return Content(contents, "text/plain");
    }
    catch (Exception ex)
    {
        return StatusCode(500, $"Error reading file: {ex.Message}");
    }
}
```

Using the payload:  http://localhost:5001/api/pathTraversal/vuln?filename=/etc/passwd  
the endpoint will return the contents of the file /etc/passwd and circumvent the base directory.

## Mitigations
Input validation by restricting certain characters can be helpful, but there are many ways to bypass such checks.  
To be sure your resulting path is valid it must be normalized and compared to it's expected base path.

### Corrected Endpoint
```csharp
string baseDir = "static/files/nutrition";

string path = Path.Combine(Directory.GetCurrentDirectory(), baseDir, filename);

string absPath = Path.GetFullPath(path);
```
Using Path.GetFullPath will normalize the path by converting it to an absolute path.  
i.e. app/../src/data -> src/data

```csharp
string basePath = Path.Combine(Directory.GetCurrentDirectory(), baseDir);
```
You can then verify your absolute path starts as intended and belongs in the proper scope with case ignored added to avoid false-positives
```csharp
if (!absPath.StartsWith(basePath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
{
    return BadRequest("Access Denied: Invalid Path.");
}
```

The payload:  http://localhost:5001/api/pathTraversal/vuln?filename=/etc/passwd  
will now result in a 400 Bad Request