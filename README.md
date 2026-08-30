[![](https://img.shields.io/nuget/v/soenneker.security.parsers.basicauth.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.security.parsers.basicauth/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.security.parsers.basicauth/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.security.parsers.basicauth/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.security.parsers.basicauth.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.security.parsers.basicauth/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.security.parsers.basicauth/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.security.parsers.basicauth/actions/workflows/codeql.yml)

# Soenneker.Security.Parsers.BasicAuth

A low-allocation parser for HTTP Basic credentials in an ASP.NET Core `HttpContext`.

## Installation

```bash
dotnet add package Soenneker.Security.Parsers.BasicAuth
```

## Usage

The returned spans point into a pooled character buffer. Always return that buffer in a `finally` block after the last credential comparison:

```csharp
using System.Security.Cryptography;
using System.Text;
using Soenneker.Security.Parsers.BasicAuth;

char[]? credentialBuffer = null;

try
{
    if (!BasicAuthParser.TryReadBasicCredentials(
            httpContext,
            out ReadOnlySpan<char> username,
            out ReadOnlySpan<char> password,
            out credentialBuffer))
    {
        return Results.Unauthorized();
    }

    bool usernameMatches = username.SequenceEqual(configuredUsername);
    byte[] suppliedPassword = Encoding.UTF8.GetBytes(password);

    try
    {
        bool passwordMatches = CryptographicOperations.FixedTimeEquals(
            suppliedPassword,
            configuredPasswordUtf8);

        return usernameMatches && passwordMatches
            ? Results.Ok()
            : Results.Unauthorized();
    }
    finally
    {
        CryptographicOperations.ZeroMemory(suppliedPassword);
    }
}
finally
{
    BasicAuthParser.Clear(credentialBuffer);
}
```

`configuredPasswordUtf8` should be prepared outside the request path and protected like the original secret. In most applications, validate a password through the application's password hasher or identity provider rather than storing a reversible plaintext credential.

## Parsing behavior

- Reads the first `Authorization` header value and accepts the `Basic` scheme case-insensitively.
- Rejects missing or malformed Base64, headers above 8 KiB, and decoded credentials without a non-empty username and password separated by the first colon.
- Allows additional colons in the password.
- Returns spans rather than username/password strings, avoiding immutable secret strings during parsing.
- On success, transfers one rented character buffer to the caller. Call `BasicAuthParser.Clear` exactly once after the spans are no longer used.
- On failure, clears and returns any buffer it rented; the returned buffer value is `null`.

Basic authentication only Base64-encodes credentials; it does not encrypt them. Accept it only over HTTPS, avoid logging the header or decoded values, and apply rate limiting and credential-rotation controls appropriate to the endpoint.
