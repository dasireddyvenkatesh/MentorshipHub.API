using MentorshipHub.API.Application.Interfaces.Auth;

namespace MentorshipHub.API.Application.Classes.Auth
{
    public class PasswordHasher : IPasswordHasher
    {
        public string Hash(string password)
            => BCrypt.Net.BCrypt.HashPassword(password);

        public bool Verify(string hash, string password)
            => BCrypt.Net.BCrypt.Verify(password, hash);
    }
}
