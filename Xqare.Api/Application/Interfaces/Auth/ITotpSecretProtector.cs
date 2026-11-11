namespace Xqare.Api.Application.Interfaces.Auth
{
    public interface ITotpSecretProtector
    {
        bool IsProtectionConfigured { get; }
        string Protect(string secret, Guid userId);
        string Unprotect(string protectedSecret, Guid userId);
        bool IsUsingActiveKey(string protectedSecret);
    }
}
