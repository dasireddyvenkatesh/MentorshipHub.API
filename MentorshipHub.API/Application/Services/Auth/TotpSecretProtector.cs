using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using MentorshipHub.API.Application.Interfaces.Auth;
using Microsoft.AspNetCore.DataProtection;

namespace MentorshipHub.API.Application.Classes.Auth
{
    /// <summary>
    /// Encrypts new TOTP secrets with versioned AES-256-GCM keys supplied through
    /// Azure App Service settings. The Data Protection protector is retained only
    /// to decrypt legacy values created before the AES-GCM format was introduced.
    /// </summary>
    public sealed class TotpSecretProtector : ITotpSecretProtector, IDisposable
    {
        private const string FormatPrefix = "xqare:aesgcm:";
        private const int KeySizeBytes = 32;
        private const int NonceSizeBytes = 12;
        private const int TagSizeBytes = 16;
        private const string FormatVersion = "v1";

        private readonly IDataProtector _legacyProtector;
        private readonly IReadOnlyDictionary<int, byte[]> _keys;
        private readonly int? _activeKeyVersion;

        public TotpSecretProtector(
            IDataProtectionProvider dataProtectionProvider,
            IConfiguration configuration,
            ILogger<TotpSecretProtector> logger)
        {
            _legacyProtector = dataProtectionProvider.CreateProtector(
                "XQARE.MentorshipHub.API.TotpSecret.v1");

            var configuredKeys = new Dictionary<int, byte[]>();
            foreach (var entry in configuration.GetSection("Totp:EncryptionKeys").GetChildren())
            {
                if (!int.TryParse(entry.Key, NumberStyles.None, CultureInfo.InvariantCulture, out var version) ||
                    version <= 0 ||
                    string.IsNullOrWhiteSpace(entry.Value))
                {
                    logger.LogWarning("Ignoring an invalid TOTP encryption-key setting.");
                    continue;
                }

                try
                {
                    var key = Convert.FromBase64String(entry.Value);
                    if (key.Length != KeySizeBytes)
                    {
                        logger.LogWarning(
                            "Ignoring TOTP encryption key version {KeyVersion}: AES-256 keys must decode to 32 bytes.",
                            version);
                        CryptographicOperations.ZeroMemory(key);
                        continue;
                    }

                    configuredKeys[version] = key;
                }
                catch (FormatException)
                {
                    logger.LogWarning(
                        "Ignoring TOTP encryption key version {KeyVersion}: its value is not valid Base64.",
                        version);
                }
            }

            _keys = configuredKeys;

            if (int.TryParse(
                    configuration["Totp:ActiveKeyVersion"],
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out var activeVersion) &&
                activeVersion > 0 &&
                configuredKeys.ContainsKey(activeVersion))
            {
                _activeKeyVersion = activeVersion;
            }
            else
            {
                _activeKeyVersion = null;
                logger.LogWarning(
                    "TOTP enrollment is disabled because Totp:ActiveKeyVersion does not identify a valid configured AES-256 key.");
            }
        }

        public bool IsProtectionConfigured
            => _activeKeyVersion.HasValue && _keys.ContainsKey(_activeKeyVersion.Value);

        public string Protect(string secret, Guid userId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secret);

            if (!IsProtectionConfigured)
                throw new InvalidOperationException(
                    "TOTP encryption is not configured. Add a valid 32-byte Base64 key and active key version to application settings.");

            var keyVersion = _activeKeyVersion!.Value;
            var key = _keys[keyVersion];
            var nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
            var plaintext = Encoding.UTF8.GetBytes(secret);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagSizeBytes];
            var associatedData = CreateAssociatedData(userId, keyVersion);

            try
            {
                using var aes = new AesGcm(key, TagSizeBytes);
                aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

                return string.Join(':',
                    "xqare",
                    "aesgcm",
                    FormatVersion,
                    keyVersion.ToString(CultureInfo.InvariantCulture),
                    Convert.ToBase64String(nonce),
                    Convert.ToBase64String(ciphertext),
                    Convert.ToBase64String(tag));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
                CryptographicOperations.ZeroMemory(associatedData);
            }
        }

        public string Unprotect(string protectedSecret, Guid userId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(protectedSecret);

            // Values created before the AES-GCM cutover are still readable while
            // their original Data Protection key ring is retained.
            if (!protectedSecret.StartsWith(FormatPrefix, StringComparison.Ordinal))
                return _legacyProtector.Unprotect(protectedSecret);

            var parts = protectedSecret.Split(':');
            if (parts.Length != 7 ||
                parts[0] != "xqare" ||
                parts[1] != "aesgcm" ||
                parts[2] != FormatVersion ||
                !int.TryParse(parts[3], NumberStyles.None, CultureInfo.InvariantCulture, out var keyVersion) ||
                !_keys.TryGetValue(keyVersion, out var key))
            {
                throw new CryptographicException("The stored TOTP secret format or key version is not supported.");
            }

            try
            {
                var nonce = Convert.FromBase64String(parts[4]);
                var ciphertext = Convert.FromBase64String(parts[5]);
                var tag = Convert.FromBase64String(parts[6]);

                if (nonce.Length != NonceSizeBytes || tag.Length != TagSizeBytes)
                    throw new CryptographicException("The stored TOTP secret has invalid cryptographic parameters.");

                var plaintext = new byte[ciphertext.Length];
                var associatedData = CreateAssociatedData(userId, keyVersion);

                try
                {
                    using var aes = new AesGcm(key, TagSizeBytes);
                    aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
                    return new UTF8Encoding(false, true).GetString(plaintext);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                    CryptographicOperations.ZeroMemory(associatedData);
                }
            }
            catch (FormatException exception)
            {
                throw new CryptographicException("The stored TOTP secret is malformed.", exception);
            }
        }

        public bool IsUsingActiveKey(string protectedSecret)
        {
            if (!IsProtectionConfigured ||
                string.IsNullOrWhiteSpace(protectedSecret) ||
                !protectedSecret.StartsWith(FormatPrefix, StringComparison.Ordinal))
            {
                return false;
            }

            var parts = protectedSecret.Split(':');
            return parts.Length == 7 &&
                   parts[0] == "xqare" &&
                   parts[1] == "aesgcm" &&
                   parts[2] == FormatVersion &&
                   int.TryParse(parts[3], NumberStyles.None, CultureInfo.InvariantCulture, out var version) &&
                   version == _activeKeyVersion;
        }

        public void Dispose()
        {
            foreach (var key in _keys.Values)
                CryptographicOperations.ZeroMemory(key);
        }

        private static byte[] CreateAssociatedData(Guid userId, int keyVersion)
            => Encoding.UTF8.GetBytes(
                $"XQARE:TOTP:{FormatVersion}:{userId:N}:{keyVersion.ToString(CultureInfo.InvariantCulture)}");
    }
}
