using Microsoft.AspNetCore.DataProtection;
using MentorshipHub.API.Application.Interfaces.Auth;
using Microsoft.AspNetCore.Hosting;

namespace MentorshipHub.API.Application.Classes.Auth
{
    public sealed class TotpSecretProtector : ITotpSecretProtector
    {
        private readonly IDataProtector _protector;
        private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment _environment;

        public TotpSecretProtector(
            IDataProtectionProvider provider,
            IConfiguration configuration,
            IWebHostEnvironment environment)
        {
            _protector = provider.CreateProtector("XQARE.MentorshipHub.API.TotpSecret.v1");
            _configuration = configuration;
            _environment = environment;
        }

        // Local Development may use the developer key ring. Deployed environments
        // must provide a certificate-protected Data Protection key ring.
        public bool IsProtectionConfigured =>
            _environment.IsDevelopment() ||
            !string.IsNullOrWhiteSpace(_configuration["DataProtection:CertificateThumbprint"]);

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
