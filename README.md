# SecureCrypto

Eine hochsichere, benutzerfreundliche Kryptographie-Bibliothek für .NET mit AES-256-GCM Verschlüsselung.

## Features

- **AES-256-GCM Verschlüsselung**: Moderne, sichere Verschlüsselung mit Authentifizierung
- **Versioniertes Format**: Zukunftssichere Datenstruktur für Updates
- **Einfache API**: Nur eine öffentliche `Crypto` Klasse für alle Operationen
- **Passwort-basiert**: PBKDF2 Key-Derivation mit 100.000 Iterationen
- **File-Unterstützung**: Direkte Verschlüsselung von Dateien
- **Sichere Implementierung**: Automatisches Löschen sensibler Daten aus dem Speicher

## Installation

```bash
dotnet add package SecureCrypto
```

## Verwendung

### Text Verschlüsselung

```csharp
using Crypto;

// Text verschlüsseln
string plaintext = "Geheimer Text";
string password = "MeinSicheresPasswort123!";
string encrypted = Crypto.Encrypt(plaintext, password);

// Text entschlüsseln
string decrypted = Crypto.Decrypt(encrypted, password);
```

### Byte-Array Verschlüsselung

```csharp
// Bytes verschlüsseln
byte[] data = Encoding.UTF8.GetBytes("Sensitive data");
byte[] encryptedBytes = Crypto.EncryptBytes(data, password);

// Bytes entschlüsseln
byte[] decryptedBytes = Crypto.DecryptBytes(encryptedBytes, password);
```

### Datei Verschlüsselung

```csharp
// Datei verschlüsseln
Crypto.EncryptFile("input.txt", "encrypted.dat", password);

// Datei entschlüsseln
Crypto.DecryptFile("encrypted.dat", "decrypted.txt", password);
```

### Sicheres Passwort generieren

```csharp
string securePassword = Crypto.GenerateSecurePassword(32);
```

## Sicherheitsfeatures

- **AES-256-GCM**: Authenticated Encryption with Associated Data (AEAD)
- **PBKDF2**: 100.000 Iterationen mit SHA-256
- **Zufällige Salts**: Unique salt für jeden Verschlüsselungsvorgang
- **Zufällige Nonces**: Unique nonce für jeden Verschlüsselungsvorgang
- **Memory Clearing**: Automatisches Löschen sensibler Daten
- **Versionierung**: Zukunftssichere Datenstruktur

## Architektur

Die Bibliothek verwendet eine saubere Architektur:
- **Öffentliche API**: `Crypto` Klasse - einfach zu verwenden
- **Private Implementierung**: `HighlySecureAuthenticatedVersionedCipher` - interne Sicherheitslogik

Dies gewährleistet eine einfache Benutzung bei maximaler Sicherheit.

## Lizenz

MIT License
