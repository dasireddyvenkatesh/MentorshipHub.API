namespace MentorshipHub.API.Application.Interfaces.Auth
{
    public interface ITotpSecretProtector
    {
        bool IsProtectionConfigured { get; }
        string Protect(string secret);
        string Unprotect(string protectedSecret);
    }
}
