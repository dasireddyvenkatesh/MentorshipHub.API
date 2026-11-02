namespace MentorshipHub.API.Application.Interfaces.Auth
{
    public interface ITotpSecretProtector
    {
        string Protect(string secret);
        string Unprotect(string protectedSecret);
    }
}
