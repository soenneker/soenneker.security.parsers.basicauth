using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace Soenneker.Security.Parsers.BasicAuth;

/// <summary>
/// A library for basic authorization parsing
/// </summary>
public static class BasicAuthParser
{
    // Optional sanity cap to avoid giant headers (8KB of Base64 ~ 6KB bytes)
    private const int _maxBase64Chars = 8 * 1024;

    public static bool TryReadBasicCredentials(HttpContext ctx, out ReadOnlySpan<char> username, out ReadOnlySpan<char> password, out char[]? charBufferToClear)
    {
        username = default;
        password = default;
        charBufferToClear = null;

        if (!ctx.Request.Headers.TryGetValue("Authorization", out StringValues auth) || auth.Count == 0)
            return false;

        string? value = auth[0];

        if (!value.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            return false;

        ReadOnlySpan<char> b64 = value.AsSpan(6).Trim();

        if (b64.Length == 0 || b64.Length > _maxBase64Chars)
            return false;

        // Base64 -> bytes (pooled)
        int maxBytes = (b64.Length * 3) / 4 + 3;
        byte[]? bytes = ArrayPool<byte>.Shared.Rent(maxBytes);
        var bytesWritten = 0;

        try
        {
            if (!Convert.TryFromBase64Chars(b64, bytes, out bytesWritten) || bytesWritten == 0)
                return false;

            // UTF8 -> chars (pooled)
            int maxChars = Encoding.UTF8.GetMaxCharCount(bytesWritten);
            charBufferToClear = ArrayPool<char>.Shared.Rent(maxChars);
            int charsWritten = Encoding.UTF8.GetChars(bytes, 0, bytesWritten, charBufferToClear, 0);

            Span<char> span = charBufferToClear.AsSpan(0, charsWritten);
            int colon = span.IndexOf(':');
            if (colon <= 0 || colon == span.Length - 1)
                return false;

            username = span.Slice(0, colon);
            password = span.Slice(colon + 1);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes.AsSpan(0, bytesWritten));
            ArrayPool<byte>.Shared.Return(bytes);
        }
    }

    public static void Clear(char[]? charBuffer)
    {
        if (charBuffer is null) 
            return;

        Array.Clear(charBuffer, 0, charBuffer.Length);
        ArrayPool<char>.Shared.Return(charBuffer);
    }
}