using Crypto;
using System.Text;

Console.WriteLine("=== SecureCrypto Test Console ===\n");

try
{
    // Test 1: Basic string encryption/decryption
    Console.WriteLine("Test 1: String Encryption/Decryption");
    string plaintext = "Dies ist ein geheimer Text!";
    string password = "MeinSicheresPasswort123!";
    
    Console.WriteLine($"Original: {plaintext}");
    string encrypted = Crypto.Crypto.Encrypt(plaintext, password);
    Console.WriteLine($"Encrypted: {encrypted[..50]}...");
    
    string decrypted = Crypto.Crypto.Decrypt(encrypted, password);
    Console.WriteLine($"Decrypted: {decrypted}");
    Console.WriteLine($"Match: {plaintext == decrypted}");
    Console.WriteLine();

    // Test 2: Byte array encryption
    Console.WriteLine("Test 2: Byte Array Encryption");
    byte[] data = Encoding.UTF8.GetBytes("Sensitive binary data 🔒");
    byte[] encryptedBytes = Crypto.Crypto.EncryptBytes(data, password);
    byte[] decryptedBytes = Crypto.Crypto.DecryptBytes(encryptedBytes, password);
    
    Console.WriteLine($"Original bytes: {data.Length} bytes");
    Console.WriteLine($"Encrypted bytes: {encryptedBytes.Length} bytes");
    Console.WriteLine($"Decrypted bytes: {decryptedBytes.Length} bytes");
    Console.WriteLine($"Match: {Encoding.UTF8.GetString(decryptedBytes)}");
    Console.WriteLine();

    // Test 3: File encryption/decryption
    Console.WriteLine("Test 3: File Encryption/Decryption");
    string testFile = "test.txt";
    string encryptedFile = "test.encrypted";
    string decryptedFile = "test.decrypted.txt";
    
    File.WriteAllText(testFile, "Dies ist der Inhalt einer Test-Datei mit wichtigen Daten!");
    Console.WriteLine($"Created test file: {testFile}");
    
    Crypto.Crypto.EncryptFile(testFile, encryptedFile, password);
    Console.WriteLine($"Encrypted to: {encryptedFile}");
    
    Crypto.Crypto.DecryptFile(encryptedFile, decryptedFile, password);
    Console.WriteLine($"Decrypted to: {decryptedFile}");
    
    string originalContent = File.ReadAllText(testFile);
    string decryptedContent = File.ReadAllText(decryptedFile);
    Console.WriteLine($"Files match: {originalContent == decryptedContent}");
    Console.WriteLine();

    // Test 4: Password generation
    Console.WriteLine("Test 4: Secure Password Generation");
    for (int i = 0; i < 3; i++)
    {
        string securePassword = Crypto.Crypto.GenerateSecurePassword(16);
        Console.WriteLine($"Generated password {i + 1}: {securePassword}");
    }
    Console.WriteLine();

    // Test 5: Base64 operations
    Console.WriteLine("Test 5: Base64 Operations");
    string base64Encrypted = Crypto.Crypto.EncryptToBase64(data, password);
    byte[] base64Decrypted = Crypto.Crypto.DecryptFromBase64(base64Encrypted, password);
    
    Console.WriteLine($"Base64 encrypted: {base64Encrypted[..50]}...");
    Console.WriteLine($"Base64 decrypted matches: {Encoding.UTF8.GetString(base64Decrypted) == Encoding.UTF8.GetString(data)}");
    Console.WriteLine();

    // Test 6: Error handling
    Console.WriteLine("Test 6: Error Handling");
    try
    {
        Crypto.Crypto.Decrypt(encrypted, "wrong_password");
        Console.WriteLine("ERROR: Should have thrown exception!");
    }
    catch (UnauthorizedAccessException)
    {
        Console.WriteLine("✓ Correctly rejected wrong password");
    }

    // Cleanup
    File.Delete(testFile);
    File.Delete(encryptedFile);
    File.Delete(decryptedFile);

    Console.WriteLine("\n=== All tests completed successfully! ===");
    Console.ReadKey();
}
catch (Exception ex)
{
    Console.WriteLine($"ERROR: {ex.Message}");
    Console.WriteLine($"Stack trace: {ex.StackTrace}");
}