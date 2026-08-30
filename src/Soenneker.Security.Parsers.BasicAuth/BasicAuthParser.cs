using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace Soenneker.Security.Parsers.BasicAuth;

/// <summary>
/// Parses HTTP Basic credentials into spans backed by a caller-released pooled buffer.
/// </summary>
public static class BasicAuthParser
{
    // Optional sanity cap to avoid giant headers (8KB of Base64 ~ 6KB bytes)
    private const int _maxBase64Chars = 8 * 1024;

    /// <summary>
    /// Attempts to decode Basic authentication credentials from the request Authorization header.
    /// </summary>
    /// <param name="context">HTTP context containing the Authorization header.</param>
    /// <param name="username">Receives the decoded username when parsing succeeds.</param>
    /// <param name="password">Receives the decoded password when parsing succeeds.</param>
    /// <param name="charBufferToClear">Receives the rented character buffer on success. Pass it to <see cref="Clear"/> exactly once after using the spans.</param>
    /// <returns>true if valid Basic credentials were decoded and assigned; otherwise, false.</returns>
    public static bool TryReadBasicCredentials(HttpContext context, out ReadOnlySpan<char> username, out ReadOnlySpan<char> password, out char[]? charBufferToClear)
    {
        username = default;
        password = default;
        charBufferToClear = null;

        if (!context.Request.Headers.TryGetValue("Authorization", out StringValues auth) || auth.Count == 0)
            return false;

        string? value = auth[0];

        if (value is null || !value.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            return false;

        ReadOnlySpan<char> b64 = value.AsSpan(6).Trim();

        if (b64.Length == 0 || b64.Length > _maxBase64Chars)
            return false;

        // Base64 -> bytes (pooled)
        int maxBytes = b64.Length * 3 / 4 + 3;
        byte[]? bytes = ArrayPool<byte>.Shared.Rent(maxBytes);
        var bytesWritten = 0;
        char[]? rentedChars = null;

        try
        {
            if (!Convert.TryFromBase64Chars(b64, bytes, out bytesWritten) || bytesWritten == 0)
                return false;

            // UTF8 -> chars (pooled)
            int maxChars = Encoding.UTF8.GetMaxCharCount(bytesWritten);
            rentedChars = ArrayPool<char>.Shared.Rent(maxChars);
            int charsWritten = Encoding.UTF8.GetChars(bytes, 0, bytesWritten, rentedChars, 0);

            Span<char> span = rentedChars.AsSpan(0, charsWritten);
            int colon = span.IndexOf(':');
            if (colon <= 0 || colon == span.Length - 1)
                return false;

            username = span.Slice(0, colon);
            password = span.Slice(colon + 1);
            charBufferToClear = rentedChars;
            rentedChars = null;
            return true;
        }
        finally
        {
            if (rentedChars is not null)
            {
                Array.Clear(rentedChars, 0, rentedChars.Length);
                ArrayPool<char>.Shared.Return(rentedChars);
            }

            CryptographicOperations.ZeroMemory(bytes.AsSpan(0, bytesWritten));
            ArrayPool<byte>.Shared.Return(bytes);
        }
    }

    /// <summary>
    /// Zeros and returns a character buffer received from <see cref="TryReadBasicCredentials"/>.
    /// </summary>
    /// <param name="charBuffer">The rented buffer to clear and return, or <see langword="null"/>.</param>
    public static void Clear(char[]? charBuffer)
    {
        if (charBuffer is null) 
            return;

        Array.Clear(charBuffer, 0, charBuffer.Length);
        ArrayPool<char>.Shared.Return(charBuffer);
    }
}
