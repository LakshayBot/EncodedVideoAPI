namespace EncodedVideoProject.Models;

public class EncryptionRequest
{
    public string Algorithm { get; set; } = "AES";
    public string Key { get; set; } = string.Empty;
    public string InputMode { get; set; } = "TEXT"; // TEXT or FILE
}