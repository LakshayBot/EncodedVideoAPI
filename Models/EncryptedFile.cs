using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace EncodedVideoProject.Models;

public class EncryptedFile
{
    [Key]
    public Guid Id { get; set; }
    
    [Required]
    public string FileName { get; set; } = string.Empty;
    
    [Required]
    public string ContentType { get; set; } = string.Empty;
    
    public long FileSize { get; set; }
    
    public byte[]? FileContent { get; set; }
    
    public string? FilePath { get; set; }
    
    [Required]
    public string KeyId { get; set; } = string.Empty; // This is the foreign key property
    
    [ForeignKey("KeyId")]
    public virtual EncryptionKey? EncryptionKey { get; set; }
    
    public string? IVId { get; set; }
    
    [Required]
    public string Algorithm { get; set; } = "AES";
    
    public int? VideoWidth { get; set; }
    
    public int? VideoHeight { get; set; }
    
    public double? VideoDuration { get; set; }
    
    public DateTime CreatedAt { get; set; }
    
    public DateTime? ModifiedAt { get; set; }
    
    // Navigation properties
    public Guid? UserId { get; set; }
    
    [ForeignKey("UserId")]
    public virtual User? User { get; set; }
}