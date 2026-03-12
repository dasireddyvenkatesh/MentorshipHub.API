namespace MentorshipHub.API.Application.Interfaces.Auth
{
    public interface IPasswordHasher
    {
        string Hash(string password);
        bool Verify(string hash, string password);
    }
}
