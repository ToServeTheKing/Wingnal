using Wingnal.Service.Attachments;
using Xunit;

namespace Wingnal.Tests.Messaging;

public class AttachmentServiceTests
{
    [Fact]
    public void Save_WritesBytesToMediaFile_WithExtension()
    {
        string dir = Path.Combine(Path.GetTempPath(), "wingnal-media-" + Guid.NewGuid().ToString("N"));
        var service = new AttachmentService(dir);
        byte[] bytes = { 0xFF, 0xD8, 0xFF, 0x01, 0x02, 0x03 };

        string path = service.Save(bytes, "jpg");

        Assert.True(File.Exists(path));
        Assert.EndsWith(".jpg", path);
        Assert.Equal(bytes, File.ReadAllBytes(path));
    }
}
