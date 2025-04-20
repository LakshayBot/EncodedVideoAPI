using System.IO;
using System.Security.Cryptography;
using System.Text;
using EncodedVideoProject.Models;
using EncodedVideoProject.Data;
using Microsoft.EntityFrameworkCore;

namespace EncodedVideoProject.Services;

public class EncryptionService : IEncryptionService
{
    private readonly ApplicationDbContext _dbContext;
    
    public EncryptionService(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }
    
    public async Task<(byte[] EncryptedData, Guid FileId)> EncryptFileAsync(Stream fileStream, string fileName, string contentType, string key, string algorithm, Guid userId)
    {
        using var memoryStream = new MemoryStream();
        await fileStream.CopyToAsync(memoryStream);
        byte[] fileBytes = memoryStream.ToArray();
        
        // Process based on algorithm
        byte[] iv;
        byte[] encryptedBytes = algorithm.ToUpper() switch
        {
            "AES" => EncryptAES(fileBytes, key, out iv),
            "DES" => EncryptDES(fileBytes, key, out iv),
            "TRIPLE_DES" => EncryptTripleDES(fileBytes, key, out iv),
            _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
        };
        
        // IMPORTANT: Extract the IV from the beginning of the encrypted data
        // so we don't double-store it
        int ivSize = algorithm.ToUpper() switch
        {
            "AES" => 16, // 128 bits
            "DES" => 8,  // 64 bits
            "TRIPLE_DES" => 8, // 64 bits
            _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
        };
        
        // Extract the actual encrypted content without the IV
        byte[] contentWithoutIV = new byte[encryptedBytes.Length - ivSize];
        Buffer.BlockCopy(encryptedBytes, ivSize, contentWithoutIV, 0, contentWithoutIV.Length);
        
        // Hash the key for storage (never store the actual key)
        string hashedKey = HashKey(key);
        
        // Create or retrieve encryption key record
        var encryptionKey = await _dbContext.EncryptionKeys
            .FirstOrDefaultAsync(k => k.HashedKey == hashedKey && k.Algorithm == algorithm);
        
        if (encryptionKey == null)
        {
            // Create a new encryption key if it doesn't exist
            encryptionKey = new EncryptionKey
            {
                Algorithm = algorithm,
                HashedKey = hashedKey,
                Salt = Convert.ToBase64String(Encoding.UTF8.GetBytes("EncryptionSalt")),
                IV = Convert.ToBase64String(iv)
            };
            
            _dbContext.EncryptionKeys.Add(encryptionKey);
            await _dbContext.SaveChangesAsync();
        }
        
        // Verify that the user exists
        var user = await _dbContext.Users.FindAsync(userId);
        if (user == null)
        {
            throw new InvalidOperationException($"User with ID {userId} does not exist");
        }
        
        // Create encrypted file record
        var encryptedFile = new EncryptedFile
        {
            Id = Guid.NewGuid(),
            FileName = fileName,
            ContentType = contentType,
            FileSize = fileBytes.Length,
            Algorithm = algorithm,
            KeyId = encryptionKey.Id,
            IVId = Convert.ToBase64String(iv),
            FileContent = contentWithoutIV, // Store content without the IV
            CreatedAt = DateTime.UtcNow,
            UserId = userId  // Set the user ID
        };
        
        _dbContext.EncryptedFiles.Add(encryptedFile);
        await _dbContext.SaveChangesAsync();
        
        return (encryptedBytes, encryptedFile.Id); // Return the full encrypted bytes including IV
    }
    
    public async Task<byte[]> DecryptFileAsync(Stream fileStream, string key, string algorithm)
    {
        using var memoryStream = new MemoryStream();
        await fileStream.CopyToAsync(memoryStream);
        byte[] fileBytes = memoryStream.ToArray();
        
        // For direct file decryption, assume the IV is at the beginning of the file
        // Extract IV size based on algorithm
        int ivSize = algorithm.ToUpper() switch
        {
            "AES" => 16, // 128 bits
            "DES" => 8,  // 64 bits
            "TRIPLE_DES" => 8, // 64 bits
            _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
        };
        
        if (fileBytes.Length <= ivSize)
            throw new InvalidOperationException("Encrypted data is too small to contain an IV");
        
        byte[] iv = new byte[ivSize];
        byte[] encryptedData = new byte[fileBytes.Length - ivSize];
        
        Buffer.BlockCopy(fileBytes, 0, iv, 0, ivSize);
        Buffer.BlockCopy(fileBytes, ivSize, encryptedData, 0, encryptedData.Length);
        
        return algorithm.ToUpper() switch
        {
            "AES" => DecryptAES(encryptedData, key, iv),
            "DES" => DecryptDES(encryptedData, key, iv),
            "TRIPLE_DES" => DecryptTripleDES(encryptedData, key, iv),
            _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
        };
    }
    
    public async Task<byte[]> DecryptFileByIdAsync(Guid fileId, string key)
    {
        var encryptedFile = await _dbContext.EncryptedFiles
            .Include(e => e.EncryptionKey)
            .FirstOrDefaultAsync(e => e.Id == fileId)
            ?? throw new FileNotFoundException($"Encrypted file with ID {fileId} not found");
            
        if (encryptedFile.FileContent == null)
            throw new InvalidOperationException("File content is not stored in the database");
            
        // Get algorithm and IV from the record
        string algorithm = encryptedFile.Algorithm;
        byte[] iv = Convert.FromBase64String(encryptedFile.IVId ?? 
            throw new InvalidOperationException("IV is missing from the database record"));
        
        // IMPORTANT: The FileContent should NOT include the IV since we're storing it separately
        return algorithm.ToUpper() switch
        {
            "AES" => DecryptAES(encryptedFile.FileContent, key, iv),
            "DES" => DecryptDES(encryptedFile.FileContent, key, iv),
            "TRIPLE_DES" => DecryptTripleDES(encryptedFile.FileContent, key, iv),
            _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
        };
    }

    public string EncryptText(string plainText, string key, string algorithm)
    {
        byte[] textBytes = Encoding.UTF8.GetBytes(plainText);
        byte[] encryptedBytes = algorithm.ToUpper() switch
        {
            "AES" => EncryptAES(textBytes, key, out _),
            "DES" => EncryptDES(textBytes, key, out _),
            "TRIPLE_DES" => EncryptTripleDES(textBytes, key, out _),
            _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
        };
        
        return Convert.ToBase64String(encryptedBytes);
    }

    public string DecryptText(string cipherText, string key, string algorithm)
    {
        byte[] encryptedBytes = Convert.FromBase64String(cipherText);
        byte[] decryptedBytes = algorithm.ToUpper() switch
        {
            "AES" => DecryptAES(encryptedBytes, key),
            "DES" => DecryptDES(encryptedBytes, key),
            "TRIPLE_DES" => DecryptTripleDES(encryptedBytes, key),
            _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
        };
        
        return Encoding.UTF8.GetString(decryptedBytes);
    }
    
    public async Task<IEnumerable<EncryptedFile>> GetAllEncryptedFilesAsync()
    {
        return await _dbContext.EncryptedFiles
            .OrderByDescending(f => f.CreatedAt)
            .ToListAsync();
    }
    
    public async Task<IEnumerable<EncryptedFile>> GetUserEncryptedFilesAsync(Guid userId)
    {
        return await _dbContext.EncryptedFiles
            .Where(f => f.UserId == userId)
            .OrderByDescending(f => f.CreatedAt)
            .ToListAsync();
    }
    
    public async Task<EncryptedFile?> GetEncryptedFileByIdAsync(Guid id)
    {
        return await _dbContext.EncryptedFiles.FindAsync(id);
    }

    private byte[] EncryptAES(byte[] data, string key, out byte[] iv)
    {
        using Aes aes = Aes.Create();
        aes.Key = DeriveKeyBytes(key, aes.KeySize / 8);
        aes.GenerateIV();
        iv = aes.IV;
        
        using MemoryStream ms = new MemoryStream();
        
        // Include IV at the beginning of the encrypted data
        ms.Write(iv, 0, iv.Length);
        
        using CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
        cs.Write(data, 0, data.Length);
        cs.FlushFinalBlock();
        
        return ms.ToArray();
    }

    private byte[] DecryptAES(byte[] data, string key, byte[] iv)
    {
        using Aes aes = Aes.Create();
        aes.Key = DeriveKeyBytes(key, aes.KeySize / 8);
        aes.IV = iv;
        
        using MemoryStream ms = new MemoryStream();
        using CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write);
        
        cs.Write(data, 0, data.Length);
        cs.FlushFinalBlock();
        
        return ms.ToArray();
    }

    private byte[] DecryptAES(byte[] data, string key)
    {
        using Aes aes = Aes.Create();
        int ivSize = aes.BlockSize / 8;
        
        if (data.Length <= ivSize)
            throw new InvalidOperationException("Encrypted data is too small to contain an IV");
            
        byte[] iv = new byte[ivSize];
        byte[] encryptedData = new byte[data.Length - ivSize];
        
        Buffer.BlockCopy(data, 0, iv, 0, ivSize);
        Buffer.BlockCopy(data, ivSize, encryptedData, 0, encryptedData.Length);
        
        return DecryptAES(encryptedData, key, iv);
    }

    private byte[] EncryptDES(byte[] data, string key, out byte[] iv)
    {
        using DES des = DES.Create();
        des.Key = DeriveKeyBytes(key, des.KeySize / 8);
        des.GenerateIV();
        iv = des.IV;
        
        using MemoryStream ms = new MemoryStream();
        
        // Include IV at the beginning of the encrypted data
        ms.Write(iv, 0, iv.Length);
        
        using CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
        cs.Write(data, 0, data.Length);
        cs.FlushFinalBlock();
        
        return ms.ToArray();
    }

    private byte[] DecryptDES(byte[] data, string key, byte[] iv)
    {
        using DES des = DES.Create();
        des.Key = DeriveKeyBytes(key, des.KeySize / 8);
        des.IV = iv;
        
        using MemoryStream ms = new MemoryStream();
        using CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write);
        
        cs.Write(data, 0, data.Length);
        cs.FlushFinalBlock();
        
        return ms.ToArray();
    }

    private byte[] DecryptDES(byte[] data, string key)
    {
        using DES des = DES.Create();
        int ivSize = des.BlockSize / 8;
        
        if (data.Length <= ivSize)
            throw new InvalidOperationException("Encrypted data is too small to contain an IV");
            
        byte[] iv = new byte[ivSize];
        byte[] encryptedData = new byte[data.Length - ivSize];
        
        Buffer.BlockCopy(data, 0, iv, 0, ivSize);
        Buffer.BlockCopy(data, ivSize, encryptedData, 0, encryptedData.Length);
        
        return DecryptDES(encryptedData, key, iv);
    }

    private byte[] EncryptTripleDES(byte[] data, string key, out byte[] iv)
    {
        using TripleDES tdes = TripleDES.Create();
        tdes.Key = DeriveKeyBytes(key, tdes.KeySize / 8);
        tdes.GenerateIV();
        iv = tdes.IV;
        
        using MemoryStream ms = new MemoryStream();
        
        // Include IV at the beginning of the encrypted data
        ms.Write(iv, 0, iv.Length);
        
        using CryptoStream cs = new CryptoStream(ms, tdes.CreateEncryptor(), CryptoStreamMode.Write);
        cs.Write(data, 0, data.Length);
        cs.FlushFinalBlock();
        
        return ms.ToArray();
    }

    private byte[] DecryptTripleDES(byte[] data, string key, byte[] iv)
    {
        using TripleDES tdes = TripleDES.Create();
        tdes.Key = DeriveKeyBytes(key, tdes.KeySize / 8);
        tdes.IV = iv;
        
        using MemoryStream ms = new MemoryStream();
        using CryptoStream cs = new CryptoStream(ms, tdes.CreateDecryptor(), CryptoStreamMode.Write);
        
        cs.Write(data, 0, data.Length);
        cs.FlushFinalBlock();
        
        return ms.ToArray();
    }

    private byte[] DecryptTripleDES(byte[] data, string key)
    {
        using TripleDES tdes = TripleDES.Create();
        int ivSize = tdes.BlockSize / 8;
        
        if (data.Length <= ivSize)
            throw new InvalidOperationException("Encrypted data is too small to contain an IV");
            
        byte[] iv = new byte[ivSize];
        byte[] encryptedData = new byte[data.Length - ivSize];
        
        Buffer.BlockCopy(data, 0, iv, 0, ivSize);
        Buffer.BlockCopy(data, ivSize, encryptedData, 0, encryptedData.Length);
        
        return DecryptTripleDES(encryptedData, key, iv);
    }

    private byte[] DeriveKeyBytes(string key, int byteCount, string salt = "")
    {
        // Use a key derivation function to create consistent keys
        using var deriveBytes = new Rfc2898DeriveBytes(
            key, 
            Encoding.UTF8.GetBytes(salt + "EncryptionSalt"), 
            1000, 
            HashAlgorithmName.SHA256);
            
        return deriveBytes.GetBytes(byteCount);
    }
    
    private string HashKey(string key)
    {
        using var sha256 = SHA256.Create();
        var keyBytes = Encoding.UTF8.GetBytes(key);
        var hashBytes = sha256.ComputeHash(keyBytes);
        return Convert.ToBase64String(hashBytes);
    }
}