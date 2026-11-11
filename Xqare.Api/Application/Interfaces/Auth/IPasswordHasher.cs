namespace Xqare.Api.Application.Interfaces.Auth
{
    public interface IPasswordHasher
    {
        string Hash(string password);
        bool Verify(string hash, string password);
        bool NeedsRehash(string? hash);
    }
}
