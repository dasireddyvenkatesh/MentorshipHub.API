using Microsoft.AspNetCore.DataProtection;
using MentorshipHub.API.Application.Interfaces.Auth;

namespace MentorshipHub.API.Application.Classes.Auth
{
    public sealed class TotpSecretProtector : ITotpSecretProtector
    {
        private readonly IDataProtector _protector;

        public TotpSecretProtector(IDataProtectionProvider provider)
        {
            _protector = provider.CreateProtector("XQARE.MentorshipHub.API.TotpSecret.v1");
        }

        public string Protect(string secret)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(secret);
            return _protector.Protect(secret);
        }

        public string Unprotect(string protectedSecret)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(protectedSecret);
            return _protector.Unprotect(protectedSecret);
        }
    }
}
