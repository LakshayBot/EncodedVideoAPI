using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using EncodedVideoProject.Services;
using EncodedVideoProject.Models;
using System.Text;
using System.Security.Claims;

namespace EncodedVideoProject.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class EncryptionController : ControllerBase
{
    private readonly IEncryptionService _encryptionService;
    private readonly IAuthService _authService;
    private readonly ILogger<EncryptionController> _logger;

    public EncryptionController(IEncryptionService encryptionService, IAuthService authService, ILogger<EncryptionController> logger)
    {
        _encryptionService = encryptionService;
        _authService = authService;
        _logger = logger;
    }

    // Helper method to get current user ID from claims
    private Guid GetCurrentUserId()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
        {
            throw new UnauthorizedAccessException("User ID not found or invalid");
        }
        return userId;
    }

    [HttpPost("encrypt")]
    public async Task<IActionResult> Encrypt([FromForm] IFormFile file, [FromForm] string key, [FromForm] string algorithm = "AES")
    {
        try
        {
            // Get the current user ID
            var userId = GetCurrentUserId();

            using var fileStream = file.OpenReadStream();
            var (encryptedBytes, fileId) = await _encryptionService.EncryptFileAsync(
                fileStream, 
                file.FileName, 
                file.ContentType, 
                key, 
                algorithm,
                userId);
            
            string encryptedFileName = $"{Path.GetFileNameWithoutExtension(file.FileName)}_encrypted{Path.GetExtension(file.FileName)}";
            
            return Ok(new 
            {
                fileId,
                fileName = encryptedFileName,
                fileSize = encryptedBytes.Length,
                algorithm,
                downloadUrl = Url.Action(nameof(Download), new { id = fileId })
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error encrypting file");
            return StatusCode(500, $"Error encrypting file: {ex.Message}");
        }
    }

    [HttpPost("decrypt")]
    public async Task<IActionResult> Decrypt([FromForm] IFormFile file, [FromForm] string key, [FromForm] string algorithm = "AES")
    {
        try
        {
            using var fileStream = file.OpenReadStream();
            var decryptedBytes = await _encryptionService.DecryptFileAsync(fileStream, key, algorithm);
            
            string decryptedFileName = $"{Path.GetFileNameWithoutExtension(file.FileName)}_decrypted{Path.GetExtension(file.FileName)}";
            
            return File(decryptedBytes, "application/octet-stream", decryptedFileName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error decrypting file");
            return StatusCode(500, $"Error decrypting file: {ex.Message}");
        }
    }
    
    [HttpGet("download/{id}")]
    public async Task<IActionResult> Download(Guid id)
    {
        try
        {
            var encryptedFile = await _encryptionService.GetEncryptedFileByIdAsync(id);
            
            if (encryptedFile == null)
                return NotFound($"File with ID {id} not found");
                
            if (encryptedFile.FileContent == null)
                return NotFound("File content not found in database");
                
            return File(encryptedFile.FileContent, encryptedFile.ContentType, encryptedFile.FileName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error downloading encrypted file");
            return StatusCode(500, $"Error downloading file: {ex.Message}");
        }
    }
    
    [HttpPost("decrypt/{id}")]
    public async Task<IActionResult> DecryptById(Guid id, [FromForm] string key)
    {
        try
        {
            var encryptedFile = await _encryptionService.GetEncryptedFileByIdAsync(id);
            
            if (encryptedFile == null)
                return NotFound($"File with ID {id} not found");
                
            var decryptedBytes = await _encryptionService.DecryptFileByIdAsync(id, key);
            
            string decryptedFileName = $"{Path.GetFileNameWithoutExtension(encryptedFile.FileName)}_decrypted{Path.GetExtension(encryptedFile.FileName)}";
            
            return File(decryptedBytes, encryptedFile.ContentType, decryptedFileName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error decrypting file by ID");
            return StatusCode(500, $"Error decrypting file: {ex.Message}");
        }
    }
    
    [HttpGet("files")]
    public async Task<IActionResult> GetEncryptedFiles()
    {
        try
        {
            // Get the current user ID
            var userId = GetCurrentUserId();
            
            var files = await _encryptionService.GetUserEncryptedFilesAsync(userId);
            
            return Ok(files.Select(f => new
            {
                f.Id,
                f.FileName,
                f.ContentType,
                f.FileSize,
                f.Algorithm,
                f.CreatedAt,
                DownloadUrl = Url.Action(nameof(Download), new { id = f.Id })
            }));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving encrypted files");
            return StatusCode(500, $"Error retrieving files: {ex.Message}");
        }
    }

    [HttpPost("encrypt-text")]
    public IActionResult EncryptText([FromBody] EncryptionRequest request)
    {
        try
        {
            string encryptedText = _encryptionService.EncryptText(request.InputMode, request.Key, request.Algorithm);
            return Ok(new { encryptedText });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error encrypting text");
            return StatusCode(500, $"Error encrypting text: {ex.Message}");
        }
    }

    [HttpPost("decrypt-text")]
    public IActionResult DecryptText([FromBody] EncryptionRequest request)
    {
        try
        {
            string decryptedText = _encryptionService.DecryptText(request.InputMode, request.Key, request.Algorithm);
            return Ok(new { decryptedText });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error decrypting text");
            return StatusCode(500, $"Error decrypting text: {ex.Message}");
        }
    }
}