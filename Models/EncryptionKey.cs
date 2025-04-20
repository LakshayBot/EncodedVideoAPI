using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace EncodedVideoProject.Models;

public class EncryptionKey
{
    [Key]
    public string Id { get; set; } = Guid.NewGuid().ToString();
    
    [Required]
    public string Algorithm { get; set; } = string.Empty;
    
    // Encrypted or hashed key - not storing clear text keys
    [Required]
    public string HashedKey { get; set; } = string.Empty;
    
    // Optional salt used for this key
    public string? Salt { get; set; }
    
    // Initialization Vector (IV)
    public string? IV { get; set; }
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    // Navigation property
    public virtual ICollection<EncryptedFile> EncryptedFiles { get; set; } = new List<EncryptedFile>();
}