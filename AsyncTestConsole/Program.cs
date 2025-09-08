using Crypto;
using System.Diagnostics;
using System.Text;

Console.WriteLine("=== SecureCrypto Async Test Console ===\n");

try
{
    var cancellationTokenSource = new CancellationTokenSource();
    var token = cancellationTokenSource.Token;

    // Test 1: Basic async string encryption/decryption
    Console.WriteLine("Test 1: Async String Encryption/Decryption");
    string plaintext = "Dies ist ein geheimer Text mit Async Support! 🔐";
    string password = "MeinAsyncPasswort123!";
    
    var stopwatch = Stopwatch.StartNew();
    
    Console.WriteLine($"Original: {plaintext}");
    string encrypted = await Crypto.Crypto.EncryptAsync(plaintext, password, token);
    Console.WriteLine($"Encrypted: {encrypted[..50]}...");
    
    string decrypted = await Crypto.Crypto.DecryptAsync(encrypted, password, token);
    Console.WriteLine($"Decrypted: {decrypted}");
    Console.WriteLine($"Match: {plaintext == decrypted}");
    
    stopwatch.Stop();
    Console.WriteLine($"Time taken: {stopwatch.ElapsedMilliseconds}ms\n");

    // Test 2: Async byte array encryption
    Console.WriteLine("Test 2: Async Byte Array Encryption");
    byte[] data = Encoding.UTF8.GetBytes("Sensitive async binary data 🔒📊");
    
    stopwatch.Restart();
    byte[] encryptedBytes = await Crypto.Crypto.EncryptBytesAsync(data, password, token);
    byte[] decryptedBytes = await Crypto.Crypto.DecryptBytesAsync(encryptedBytes, password, token);
    stopwatch.Stop();
    
    Console.WriteLine($"Original bytes: {data.Length} bytes");
    Console.WriteLine($"Encrypted bytes: {encryptedBytes.Length} bytes");
    Console.WriteLine($"Decrypted bytes: {decryptedBytes.Length} bytes");
    Console.WriteLine($"Match: {Encoding.UTF8.GetString(decryptedBytes)}");
    Console.WriteLine($"Time taken: {stopwatch.ElapsedMilliseconds}ms\n");

    // Test 3: Async file operations
    Console.WriteLine("Test 3: Async File Encryption/Decryption");
    string testFile = "async_test.txt";
    string encryptedFile = "async_test.encrypted";
    string decryptedFile = "async_test.decrypted.txt";
    
    await File.WriteAllTextAsync(testFile, "Dies ist der Inhalt einer Test-Datei für Async-Operationen!", token);
    Console.WriteLine($"Created test file: {testFile}");
    
    stopwatch.Restart();
    await Crypto.Crypto.EncryptFileAsync(testFile, encryptedFile, password, token);
    Console.WriteLine($"Encrypted to: {encryptedFile}");
    
    await Crypto.Crypto.DecryptFileAsync(encryptedFile, decryptedFile, password, token);
    Console.WriteLine($"Decrypted to: {decryptedFile}");
    stopwatch.Stop();
    
    string originalContent = await File.ReadAllTextAsync(testFile, token);
    string decryptedContent = await File.ReadAllTextAsync(decryptedFile, token);
    Console.WriteLine($"Files match: {originalContent == decryptedContent}");
    Console.WriteLine($"File operations time: {stopwatch.ElapsedMilliseconds}ms\n");

    // Test 4: Async Base64 operations
    Console.WriteLine("Test 4: Async Base64 Operations");
    
    stopwatch.Restart();
    string base64Encrypted = await Crypto.Crypto.EncryptToBase64Async(data, password, token);
    byte[] base64Decrypted = await Crypto.Crypto.DecryptFromBase64Async(base64Encrypted, password, token);
    stopwatch.Stop();
    
    Console.WriteLine($"Base64 encrypted: {base64Encrypted[..50]}...");
    Console.WriteLine($"Base64 decrypted matches: {Encoding.UTF8.GetString(base64Decrypted) == Encoding.UTF8.GetString(data)}");
    Console.WriteLine($"Time taken: {stopwatch.ElapsedMilliseconds}ms\n");

    // Test 5: Parallel async operations
    Console.WriteLine("Test 5: Parallel Async Operations");
    var tasks = new List<Task<string>>();
    
    stopwatch.Restart();
    for (int i = 0; i < 5; i++)
    {
        string text = $"Parallel text {i + 1}";
        var task = Crypto.Crypto.EncryptAsync(text, password, token);
        tasks.Add(task);
    }
    
    var results = await Task.WhenAll(tasks);
    stopwatch.Stop();
    
    Console.WriteLine($"Encrypted {results.Length} texts in parallel");
    Console.WriteLine($"Parallel encryption time: {stopwatch.ElapsedMilliseconds}ms\n");

    // Test 6: Cancellation support
    Console.WriteLine("Test 6: Cancellation Support");
    var shortCancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(5));
    
    try
    {
        await Crypto.Crypto.EncryptAsync("Test text for cancellation", password, shortCancellation.Token);
        Console.WriteLine("Note: Operation completed before cancellation (very fast system)");
    }
    catch (OperationCanceledException)
    {
        Console.WriteLine("✓ Correctly handled cancellation");
    }
    
    // Test with immediate cancellation
    var immediateCancellation = new CancellationTokenSource();
    immediateCancellation.Cancel();
    
    try
    {
        await Crypto.Crypto.EncryptAsync("Test text", password, immediateCancellation.Token);
        Console.WriteLine("ERROR: Should have been cancelled immediately!");
    }
    catch (OperationCanceledException)
    {
        Console.WriteLine("✓ Correctly handled immediate cancellation");
    }

    // Test 7: Performance comparison sync vs async
    Console.WriteLine("\nTest 7: Performance Comparison (Sync vs Async)");
    string perfText = "Performance test text with some content to encrypt";
    
    // Sync version
    stopwatch.Restart();
    for (int i = 0; i < 10; i++)
    {
        var syncEncrypted = Crypto.Crypto.Encrypt(perfText, password);
        var syncDecrypted = Crypto.Crypto.Decrypt(syncEncrypted, password);
    }
    var syncTime = stopwatch.ElapsedMilliseconds;
    
    // Async version
    stopwatch.Restart();
    for (int i = 0; i < 10; i++)
    {
        var asyncEncrypted = await Crypto.Crypto.EncryptAsync(perfText, password, token);
        var asyncDecrypted = await Crypto.Crypto.DecryptAsync(asyncEncrypted, password, token);
    }
    var asyncTime = stopwatch.ElapsedMilliseconds;
    
    Console.WriteLine($"Sync (10 operations): {syncTime}ms");
    Console.WriteLine($"Async (10 operations): {asyncTime}ms");

    // Cleanup
    File.Delete(testFile);
    File.Delete(encryptedFile);
    File.Delete(decryptedFile);

    Console.WriteLine("\n=== All async tests completed successfully! ===");
    Console.ReadKey();
}
catch (Exception ex)
{
    Console.WriteLine($"ERROR: {ex.Message}");
    Console.WriteLine($"Stack trace: {ex.StackTrace}");
}

Console.ReadKey();