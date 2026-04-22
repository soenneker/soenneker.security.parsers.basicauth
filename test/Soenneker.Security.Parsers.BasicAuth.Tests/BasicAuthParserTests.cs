using Soenneker.Tests.HostedUnit;

namespace Soenneker.Security.Parsers.BasicAuth.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class BasicAuthParserTests : HostedUnitTest
{
    public BasicAuthParserTests(Host host) : base(host)
    {
    }

    [Test]
    public void Default()
    {

    }
}
