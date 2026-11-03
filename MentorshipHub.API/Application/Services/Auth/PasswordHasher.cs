using System.Text;
using MentorshipHub.API.Application.Interfaces.Auth;

namespace MentorshipHub.API.Application.Classes.Auth
{
    public class PasswordHasher : IPasswordHasher
    {
        // Prefix marks the hashing scheme because enhanced and regular BCrypt
        // hashes otherwise share the same standard BCrypt string format.
        private const string EnhancedHashPrefix = "$xqare$bcrypt-sha384$v1$";
        private const int BCryptMaximumPasswordBytes = 72;

        public string Hash(string password)
        {
            ArgumentNullException.ThrowIfNull(password);

            var bcryptHash = BCrypt.Net.BCrypt.EnhancedHashPassword(
                password,
                BCrypt.Net.HashType.SHA384);

            return EnhancedHashPrefix + bcryptHash;
        }

        public bool Verify(string hash, string password)
        {
            if (string.IsNullOrWhiteSpace(hash) || password is null)
                return false;

            if (hash.StartsWith(EnhancedHashPrefix, StringComparison.Ordinal))
            {
                var bcryptHash = hash[EnhancedHashPrefix.Length..];

                return BCrypt.Net.BCrypt.EnhancedVerify(
                    password,
                    bcryptHash,
                    BCrypt.Net.HashType.SHA384);
            }

            // Legacy raw BCrypt only incorporates the first 72 UTF-8 bytes.
            // Reject longer candidates rather than authenticating a truncated prefix.
            if (Encoding.UTF8.GetByteCount(password) > BCryptMaximumPasswordBytes)
                return false;

            return BCrypt.Net.BCrypt.Verify(password, hash);
        }

        public bool NeedsRehash(string? hash)
            => !string.IsNullOrWhiteSpace(hash) &&
               !hash.StartsWith(EnhancedHashPrefix, StringComparison.Ordinal);
    }
}
