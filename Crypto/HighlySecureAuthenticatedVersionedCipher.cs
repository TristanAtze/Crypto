using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Crypto
{
    internal class HighlySecureAuthenticatedVersionedCipher
    {
        private const int KeySize = 32; // 256 bits for AES-256
        private const int NonceSize = 12; // 96 bits for AES-GCM
        private const int TagSize = 16; // 128 bits for authentication tag
        private const int SaltSize = 16; // 128 bits for PBKDF2 salt
        private const int Iterations = 600000; // PBKDF2 iterations
        private const byte Version = 1;

        internal static byte[] Encrypt(string plaintext, string password)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw new ArgumentException("Plaintext cannot be null or empty", nameof(plaintext));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var salt = GenerateRandomBytes(SaltSize);
            var nonce = GenerateRandomBytes(NonceSize);
            var key = DeriveKey(password, salt);

            using var aesGcm = new AesGcm(key, TagSize);
            var ciphertext = new byte[plaintextBytes.Length];
            var tag = new byte[TagSize];
            
            aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag);

            // Create versioned structure: Version(1) + Salt(16) + Nonce(12) + Tag(16) + Ciphertext(variable)
            var result = new byte[1 + SaltSize + NonceSize + TagSize + ciphertext.Length];
            var offset = 0;
            
            result[offset++] = Version;
            Array.Copy(salt, 0, result, offset, SaltSize);
            offset += SaltSize;
            Array.Copy(nonce, 0, result, offset, NonceSize);
            offset += NonceSize;
            Array.Copy(tag, 0, result, offset, TagSize);
            offset += TagSize;
            Array.Copy(ciphertext, 0, result, offset, ciphertext.Length);

            // Clear sensitive data
            Array.Clear(key);
            Array.Clear(plaintextBytes);
            
            return result;
        }

        internal static string Decrypt(byte[] encryptedData, string password)
        {
            if (encryptedData == null || encryptedData.Length == 0)
                throw new ArgumentException("Encrypted data cannot be null or empty", nameof(encryptedData));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            var minSize = 1 + SaltSize + NonceSize + TagSize;
            if (encryptedData.Length < minSize)
                throw new ArgumentException("Encrypted data is too short to be valid");

            var offset = 0;
            var version = encryptedData[offset++];
            
            if (version != Version)
                throw new NotSupportedException($"Unsupported version: {version}");

            var salt = new byte[SaltSize];
            Array.Copy(encryptedData, offset, salt, 0, SaltSize);
            offset += SaltSize;

            var nonce = new byte[NonceSize];
            Array.Copy(encryptedData, offset, nonce, 0, NonceSize);
            offset += NonceSize;

            var tag = new byte[TagSize];
            Array.Copy(encryptedData, offset, tag, 0, TagSize);
            offset += TagSize;

            var ciphertext = new byte[encryptedData.Length - offset];
            Array.Copy(encryptedData, offset, ciphertext, 0, ciphertext.Length);

            var key = DeriveKey(password, salt);

            using var aesGcm = new AesGcm(key, TagSize);
            var plaintext = new byte[ciphertext.Length];
            
            try
            {
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
                var result = Encoding.UTF8.GetString(plaintext);
                
                // Clear sensitive data
                Array.Clear(key);
                Array.Clear(plaintext);
                
                return result;
            }
            catch (AuthenticationTagMismatchException)
            {
                Array.Clear(key);
                throw new UnauthorizedAccessException("Invalid password or corrupted data");
            }
        }

        internal static byte[] EncryptBytes(byte[] data, string password)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("Data cannot be null or empty", nameof(data));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            var salt = GenerateRandomBytes(SaltSize);
            var nonce = GenerateRandomBytes(NonceSize);
            var key = DeriveKey(password, salt);

            using var aesGcm = new AesGcm(key, TagSize);
            var ciphertext = new byte[data.Length];
            var tag = new byte[TagSize];
            
            aesGcm.Encrypt(nonce, data, ciphertext, tag);

            var result = new byte[1 + SaltSize + NonceSize + TagSize + ciphertext.Length];
            var offset = 0;
            
            result[offset++] = Version;
            Array.Copy(salt, 0, result, offset, SaltSize);
            offset += SaltSize;
            Array.Copy(nonce, 0, result, offset, NonceSize);
            offset += NonceSize;
            Array.Copy(tag, 0, result, offset, TagSize);
            offset += TagSize;
            Array.Copy(ciphertext, 0, result, offset, ciphertext.Length);

            Array.Clear(key);
            
            return result;
        }

        internal static byte[] DecryptBytes(byte[] encryptedData, string password)
        {
            if (encryptedData == null || encryptedData.Length == 0)
                throw new ArgumentException("Encrypted data cannot be null or empty", nameof(encryptedData));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            var minSize = 1 + SaltSize + NonceSize + TagSize;
            if (encryptedData.Length < minSize)
                throw new ArgumentException("Encrypted data is too short to be valid");

            var offset = 0;
            var version = encryptedData[offset++];
            
            if (version != Version)
                throw new NotSupportedException($"Unsupported version: {version}");

            var salt = new byte[SaltSize];
            Array.Copy(encryptedData, offset, salt, 0, SaltSize);
            offset += SaltSize;

            var nonce = new byte[NonceSize];
            Array.Copy(encryptedData, offset, nonce, 0, NonceSize);
            offset += NonceSize;

            var tag = new byte[TagSize];
            Array.Copy(encryptedData, offset, tag, 0, TagSize);
            offset += TagSize;

            var ciphertext = new byte[encryptedData.Length - offset];
            Array.Copy(encryptedData, offset, ciphertext, 0, ciphertext.Length);

            var key = DeriveKey(password, salt);

            using var aesGcm = new AesGcm(key, TagSize);
            var plaintext = new byte[ciphertext.Length];
            
            try
            {
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
                Array.Clear(key);
                return plaintext;
            }
            catch (AuthenticationTagMismatchException)
            {
                Array.Clear(key);
                throw new UnauthorizedAccessException("Invalid password or corrupted data");
            }
        }

        private static byte[] GenerateRandomBytes(int size)
        {
            var bytes = new byte[size];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return bytes;
        }

        private static byte[] DeriveKey(string password, byte[] salt)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(KeySize);
        }

        // Async versions
        internal static async Task<byte[]> EncryptAsync(string plaintext, string password, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw new ArgumentException("Plaintext cannot be null or empty", nameof(plaintext));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            cancellationToken.ThrowIfCancellationRequested();

            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var salt = GenerateRandomBytes(SaltSize);
            var nonce = GenerateRandomBytes(NonceSize);
            
            cancellationToken.ThrowIfCancellationRequested();
            var key = await DeriveKeyAsync(password, salt, cancellationToken);

            return await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                using var aesGcm = new AesGcm(key, TagSize);
                var ciphertext = new byte[plaintextBytes.Length];
                var tag = new byte[TagSize];
                
                aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag);

                var result = new byte[1 + SaltSize + NonceSize + TagSize + ciphertext.Length];
                var offset = 0;
                
                result[offset++] = Version;
                Array.Copy(salt, 0, result, offset, SaltSize);
                offset += SaltSize;
                Array.Copy(nonce, 0, result, offset, NonceSize);
                offset += NonceSize;
                Array.Copy(tag, 0, result, offset, TagSize);
                offset += TagSize;
                Array.Copy(ciphertext, 0, result, offset, ciphertext.Length);

                Array.Clear(key);
                Array.Clear(plaintextBytes);
                
                return result;
            }, cancellationToken);
        }

        internal static async Task<string> DecryptAsync(byte[] encryptedData, string password, CancellationToken cancellationToken = default)
        {
            if (encryptedData == null || encryptedData.Length == 0)
                throw new ArgumentException("Encrypted data cannot be null or empty", nameof(encryptedData));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            var minSize = 1 + SaltSize + NonceSize + TagSize;
            if (encryptedData.Length < minSize)
                throw new ArgumentException("Encrypted data is too short to be valid");

            cancellationToken.ThrowIfCancellationRequested();

            var offset = 0;
            var version = encryptedData[offset++];
            
            if (version != Version)
                throw new NotSupportedException($"Unsupported version: {version}");

            var salt = new byte[SaltSize];
            Array.Copy(encryptedData, offset, salt, 0, SaltSize);
            offset += SaltSize;

            var nonce = new byte[NonceSize];
            Array.Copy(encryptedData, offset, nonce, 0, NonceSize);
            offset += NonceSize;

            var tag = new byte[TagSize];
            Array.Copy(encryptedData, offset, tag, 0, TagSize);
            offset += TagSize;

            var ciphertext = new byte[encryptedData.Length - offset];
            Array.Copy(encryptedData, offset, ciphertext, 0, ciphertext.Length);

            cancellationToken.ThrowIfCancellationRequested();
            var key = await DeriveKeyAsync(password, salt, cancellationToken);

            return await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                using var aesGcm = new AesGcm(key, TagSize);
                var plaintext = new byte[ciphertext.Length];
                
                try
                {
                    aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
                    var result = Encoding.UTF8.GetString(plaintext);
                    
                    Array.Clear(key);
                    Array.Clear(plaintext);
                    
                    return result;
                }
                catch (AuthenticationTagMismatchException)
                {
                    Array.Clear(key);
                    throw new UnauthorizedAccessException("Invalid password or corrupted data");
                }
            }, cancellationToken);
        }

        internal static async Task<byte[]> EncryptBytesAsync(byte[] data, string password, CancellationToken cancellationToken = default)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("Data cannot be null or empty", nameof(data));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            cancellationToken.ThrowIfCancellationRequested();

            var salt = GenerateRandomBytes(SaltSize);
            var nonce = GenerateRandomBytes(NonceSize);
            
            cancellationToken.ThrowIfCancellationRequested();
            var key = await DeriveKeyAsync(password, salt, cancellationToken);

            return await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                using var aesGcm = new AesGcm(key, TagSize);
                var ciphertext = new byte[data.Length];
                var tag = new byte[TagSize];
                
                aesGcm.Encrypt(nonce, data, ciphertext, tag);

                var result = new byte[1 + SaltSize + NonceSize + TagSize + ciphertext.Length];
                var offset = 0;
                
                result[offset++] = Version;
                Array.Copy(salt, 0, result, offset, SaltSize);
                offset += SaltSize;
                Array.Copy(nonce, 0, result, offset, NonceSize);
                offset += NonceSize;
                Array.Copy(tag, 0, result, offset, TagSize);
                offset += TagSize;
                Array.Copy(ciphertext, 0, result, offset, ciphertext.Length);

                Array.Clear(key);
                
                return result;
            }, cancellationToken);
        }

        internal static async Task<byte[]> DecryptBytesAsync(byte[] encryptedData, string password, CancellationToken cancellationToken = default)
        {
            if (encryptedData == null || encryptedData.Length == 0)
                throw new ArgumentException("Encrypted data cannot be null or empty", nameof(encryptedData));
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            var minSize = 1 + SaltSize + NonceSize + TagSize;
            if (encryptedData.Length < minSize)
                throw new ArgumentException("Encrypted data is too short to be valid");

            cancellationToken.ThrowIfCancellationRequested();

            var offset = 0;
            var version = encryptedData[offset++];
            
            if (version != Version)
                throw new NotSupportedException($"Unsupported version: {version}");

            var salt = new byte[SaltSize];
            Array.Copy(encryptedData, offset, salt, 0, SaltSize);
            offset += SaltSize;

            var nonce = new byte[NonceSize];
            Array.Copy(encryptedData, offset, nonce, 0, NonceSize);
            offset += NonceSize;

            var tag = new byte[TagSize];
            Array.Copy(encryptedData, offset, tag, 0, TagSize);
            offset += TagSize;

            var ciphertext = new byte[encryptedData.Length - offset];
            Array.Copy(encryptedData, offset, ciphertext, 0, ciphertext.Length);

            cancellationToken.ThrowIfCancellationRequested();
            var key = await DeriveKeyAsync(password, salt, cancellationToken);

            return await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                using var aesGcm = new AesGcm(key, TagSize);
                var plaintext = new byte[ciphertext.Length];
                
                try
                {
                    aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
                    Array.Clear(key);
                    return plaintext;
                }
                catch (AuthenticationTagMismatchException)
                {
                    Array.Clear(key);
                    throw new UnauthorizedAccessException("Invalid password or corrupted data");
                }
            }, cancellationToken);
        }

        private static async Task<byte[]> DeriveKeyAsync(string password, byte[] salt, CancellationToken cancellationToken = default)
        {
            return await Task.Run(() =>
            {
                using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
                
                // Check for cancellation periodically during key derivation
                // This is the most time-consuming operation
                for (int i = 0; i < 10; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Thread.Sleep(1); // Small delay to allow cancellation checking
                }
                
                return pbkdf2.GetBytes(KeySize);
            }, cancellationToken);
        }
    }
}