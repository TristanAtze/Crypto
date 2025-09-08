using System.Text;

namespace Crypto
{
    public static class Crypto
    {
        public static string Encrypt(string plaintext, string password)
        {
            var encryptedBytes = HighlySecureAuthenticatedVersionedCipher.Encrypt(plaintext, password);
            return Convert.ToBase64String(encryptedBytes);
        }

        public static string Decrypt(string encryptedData, string password)
        {
            var encryptedBytes = Convert.FromBase64String(encryptedData);
            return HighlySecureAuthenticatedVersionedCipher.Decrypt(encryptedBytes, password);
        }

        public static byte[] EncryptBytes(byte[] data, string password)
        {
            return HighlySecureAuthenticatedVersionedCipher.EncryptBytes(data, password);
        }

        public static byte[] DecryptBytes(byte[] encryptedData, string password)
        {
            return HighlySecureAuthenticatedVersionedCipher.DecryptBytes(encryptedData, password);
        }

        public static string EncryptToBase64(byte[] data, string password)
        {
            var encryptedBytes = HighlySecureAuthenticatedVersionedCipher.EncryptBytes(data, password);
            return Convert.ToBase64String(encryptedBytes);
        }

        public static byte[] DecryptFromBase64(string encryptedBase64, string password)
        {
            var encryptedBytes = Convert.FromBase64String(encryptedBase64);
            return HighlySecureAuthenticatedVersionedCipher.DecryptBytes(encryptedBytes, password);
        }

        public static void EncryptFile(string inputFilePath, string outputFilePath, string password)
        {
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException($"Input file not found: {inputFilePath}");

            var data = File.ReadAllBytes(inputFilePath);
            var encryptedData = HighlySecureAuthenticatedVersionedCipher.EncryptBytes(data, password);
            File.WriteAllBytes(outputFilePath, encryptedData);
            
            Array.Clear(data);
        }

        public static void DecryptFile(string inputFilePath, string outputFilePath, string password)
        {
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException($"Input file not found: {inputFilePath}");

            var encryptedData = File.ReadAllBytes(inputFilePath);
            var decryptedData = HighlySecureAuthenticatedVersionedCipher.DecryptBytes(encryptedData, password);
            File.WriteAllBytes(outputFilePath, decryptedData);
            
            Array.Clear(decryptedData);
        }

        public static string GenerateSecurePassword(int length = 32)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
            var random = new Random();
            var result = new StringBuilder(length);
            
            for (int i = 0; i < length; i++)
            {
                result.Append(chars[random.Next(chars.Length)]);
            }
            
            return result.ToString();
        }

        // Async versions
        public static async Task<string> EncryptAsync(string plaintext, string password, CancellationToken cancellationToken = default)
        {
            var encryptedBytes = await HighlySecureAuthenticatedVersionedCipher.EncryptAsync(plaintext, password, cancellationToken);
            return Convert.ToBase64String(encryptedBytes);
        }

        public static async Task<string> DecryptAsync(string encryptedData, string password, CancellationToken cancellationToken = default)
        {
            var encryptedBytes = Convert.FromBase64String(encryptedData);
            return await HighlySecureAuthenticatedVersionedCipher.DecryptAsync(encryptedBytes, password, cancellationToken);
        }

        public static async Task<byte[]> EncryptBytesAsync(byte[] data, string password, CancellationToken cancellationToken = default)
        {
            return await HighlySecureAuthenticatedVersionedCipher.EncryptBytesAsync(data, password, cancellationToken);
        }

        public static async Task<byte[]> DecryptBytesAsync(byte[] encryptedData, string password, CancellationToken cancellationToken = default)
        {
            return await HighlySecureAuthenticatedVersionedCipher.DecryptBytesAsync(encryptedData, password, cancellationToken);
        }

        public static async Task<string> EncryptToBase64Async(byte[] data, string password, CancellationToken cancellationToken = default)
        {
            var encryptedBytes = await HighlySecureAuthenticatedVersionedCipher.EncryptBytesAsync(data, password, cancellationToken);
            return Convert.ToBase64String(encryptedBytes);
        }

        public static async Task<byte[]> DecryptFromBase64Async(string encryptedBase64, string password, CancellationToken cancellationToken = default)
        {
            var encryptedBytes = Convert.FromBase64String(encryptedBase64);
            return await HighlySecureAuthenticatedVersionedCipher.DecryptBytesAsync(encryptedBytes, password, cancellationToken);
        }

        public static async Task EncryptFileAsync(string inputFilePath, string outputFilePath, string password, CancellationToken cancellationToken = default)
        {
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException($"Input file not found: {inputFilePath}");

            var data = await File.ReadAllBytesAsync(inputFilePath, cancellationToken);
            var encryptedData = await HighlySecureAuthenticatedVersionedCipher.EncryptBytesAsync(data, password, cancellationToken);
            await File.WriteAllBytesAsync(outputFilePath, encryptedData, cancellationToken);
            
            Array.Clear(data);
        }

        public static async Task DecryptFileAsync(string inputFilePath, string outputFilePath, string password, CancellationToken cancellationToken = default)
        {
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException($"Input file not found: {inputFilePath}");

            var encryptedData = await File.ReadAllBytesAsync(inputFilePath, cancellationToken);
            var decryptedData = await HighlySecureAuthenticatedVersionedCipher.DecryptBytesAsync(encryptedData, password, cancellationToken);
            await File.WriteAllBytesAsync(outputFilePath, decryptedData, cancellationToken);
            
            Array.Clear(decryptedData);
        }
    }
}
