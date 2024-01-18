using Microsoft.Extensions.Caching.Distributed;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class FileDistributedCache : IDistributedCache
{
    private readonly string cacheFilePath;
    private readonly string encryptionPassword;
    private readonly Dictionary<string, CacheEntry> cacheEntries;

    public FileDistributedCache(string cacheFilePath, string encryptionPassword)
    {
        this.cacheFilePath = cacheFilePath;
        this.encryptionPassword = encryptionPassword;
        this.cacheEntries = LoadFromCacheFile();
    }

    public byte[] Get(string key)
    {
        if (cacheEntries.TryGetValue(key, out var entry))
        {
            if (entry.Expiration == null || entry.Expiration > DateTimeOffset.UtcNow)
            {
                return entry.Value;
            }
            else
            {
                cacheEntries.Remove(key);
                SaveToCacheFile();
            }
        }

        return null;
    }

    public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
    {
        var expiration = options?.AbsoluteExpiration;
        cacheEntries[key] = new CacheEntry { Key = key, Value = value, Expiration = expiration };
        SaveToCacheFile();
    }

    public void Refresh(string key)
    {
        if (cacheEntries.TryGetValue(key, out var entry))
        {
            entry.Expiration = DateTimeOffset.UtcNow.Add(entry.RelativeExpiration);
            SaveToCacheFile();
        }
    }

    public void Remove(string key)
    {
        cacheEntries.Remove(key);
        SaveToCacheFile();
    }

    private void SaveToCacheFile()
    {
        var serializedEntries = JsonConvert.SerializeObject(cacheEntries.Values);
        var encryptedData = Encrypt(serializedEntries, encryptionPassword);

        File.WriteAllText(cacheFilePath, encryptedData);
    }

    private Dictionary<string, CacheEntry> LoadFromCacheFile()
    {
        if (File.Exists(cacheFilePath))
        {
            var encryptedData = File.ReadAllText(cacheFilePath);
            var decryptedData = Decrypt(encryptedData, encryptionPassword);

            var entries = JsonConvert.DeserializeObject<List<CacheEntry>>(decryptedData) ?? new List<CacheEntry>();

            return entries.ToDictionary(entry => entry.Key);
        }

        return new Dictionary<string, CacheEntry>();
    }

    private string Encrypt(string data, string password)
    {
        using (Aes aesAlg = Aes.Create())
        {
            Rfc2898DeriveBytes keyDerivation = new Rfc2898DeriveBytes(password, aesAlg.KeySize / 8);
            aesAlg.Key = keyDerivation.GetBytes(aesAlg.KeySize / 8);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, aesAlg.CreateEncryptor(), CryptoStreamMode.Write))
                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(data);
                }

                return Convert.ToBase64String(msEncrypt.ToArray());
            }
        }
    }

    private string Decrypt(string encryptedData, string password)
    {
        using (Aes aesAlg = Aes.Create())
        {
            Rfc2898DeriveBytes keyDerivation = new Rfc2898DeriveBytes(password, aesAlg.KeySize / 8);
            aesAlg.Key = keyDerivation.GetBytes(aesAlg.KeySize / 8);

            using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(encryptedData)))
            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, aesAlg.CreateDecryptor(), CryptoStreamMode.Read))
            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
            {
                return srDecrypt.ReadToEnd();
            }
        }
    }

    private class CacheEntry
    {
        public string Key { get; set; }
        public byte[] Value { get; set; }
        public DateTimeOffset? Expiration { get; set; }
        // Add other metadata as needed
    }
}
