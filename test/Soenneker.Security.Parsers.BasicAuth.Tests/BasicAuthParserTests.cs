using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Soenneker.Tests.HostedUnit;

namespace Soenneker.Security.Parsers.BasicAuth.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class BasicAuthParserTests : HostedUnitTest
{
    public BasicAuthParserTests(Host host) : base(host)
    {
    }

    [Test]
    public async Task Valid_credentials_are_returned_and_can_be_cleared()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = "Basic dXNlcjpwYXNzd29yZA==";

        bool parsed = BasicAuthParser.TryReadBasicCredentials(context, out ReadOnlySpan<char> username, out ReadOnlySpan<char> password,
            out char[]? buffer);

        try
        {
            bool usernameMatches = username.SequenceEqual("user");
            bool passwordMatches = password.SequenceEqual("password");

            await Assert.That(parsed).IsTrue();
            await Assert.That(usernameMatches).IsTrue();
            await Assert.That(passwordMatches).IsTrue();
            await Assert.That(buffer).IsNotNull();
        }
        finally
        {
            BasicAuthParser.Clear(buffer);
        }
    }

    [Test]
    public async Task Invalid_decoded_credentials_do_not_transfer_a_buffer()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Authorization = "Basic bm8tY29sb24=";

        bool parsed = BasicAuthParser.TryReadBasicCredentials(context, out _, out _, out char[]? buffer);

        await Assert.That(parsed).IsFalse();
        await Assert.That(buffer).IsNull();
    }
}
