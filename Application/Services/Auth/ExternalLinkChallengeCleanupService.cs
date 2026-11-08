using MentorshipHub.API.Enities;
using Microsoft.EntityFrameworkCore;

namespace MentorshipHub.API.Application.Services.Auth
{
    /// <summary>
    /// Removes expired OAuth account-link challenges after a 30-day retention period.
    /// MFA challenges are deliberately excluded.
    /// </summary>
    public sealed class ExternalLinkChallengeCleanupService : BackgroundService
    {
        private static readonly TimeSpan CleanupInterval = TimeSpan.FromHours(24);
        private static readonly TimeSpan RetentionPeriod = TimeSpan.FromDays(30);

        private readonly IServiceScopeFactory _scopeFactory;
        private readonly ILogger<ExternalLinkChallengeCleanupService> _logger;

        public ExternalLinkChallengeCleanupService(
            IServiceScopeFactory scopeFactory,
            ILogger<ExternalLinkChallengeCleanupService> logger)
        {
            _scopeFactory = scopeFactory;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            using var timer = new PeriodicTimer(CleanupInterval);

            do
            {
                await CleanupExpiredChallengesAsync(stoppingToken);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }

        private async Task CleanupExpiredChallengesAsync(CancellationToken cancellationToken)
        {
            try
            {
                using var scope = _scopeFactory.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var cutoff = DateTime.UtcNow.Subtract(RetentionPeriod);

                var deletedCount = await db.MfaLoginChallenges
                    .Where(x =>
                        x.Purpose == "external-link" &&
                        x.ExpiresAt <= cutoff)
                    .ExecuteDeleteAsync(cancellationToken);

                if (deletedCount > 0)
                {
                    _logger.LogInformation(
                        "Removed {Count} expired OAuth account-link challenges older than {RetentionDays} days.",
                        deletedCount,
                        RetentionPeriod.TotalDays);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Failed to clean up expired OAuth account-link challenges.");
            }
        }
    }
}
