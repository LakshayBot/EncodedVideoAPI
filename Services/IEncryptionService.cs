using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using EncodedVideoProject.Models;

namespace EncodedVideoProject.Services;

public interface IEncryptionService
{
    Task<(byte[] EncryptedData, Guid FileId)> EncryptFileAsync(Stream fileStream, string fileName, string contentType, string key, string algorithm, Guid userId);
    Task<byte[]> DecryptFileAsync(Stream fileStream, string key, string algorithm);
    Task<byte[]> DecryptFileByIdAsync(Guid fileId, string key);
    string EncryptText(string plainText, string key, string algorithm);
    string DecryptText(string cipherText, string key, string algorithm);
    Task<IEnumerable<EncryptedFile>> GetAllEncryptedFilesAsync();
    Task<IEnumerable<EncryptedFile>> GetUserEncryptedFilesAsync(Guid userId);
    Task<EncryptedFile?> GetEncryptedFileByIdAsync(Guid id);
}