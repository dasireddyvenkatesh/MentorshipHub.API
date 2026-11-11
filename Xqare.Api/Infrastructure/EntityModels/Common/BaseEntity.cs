namespace MentorshipHub.API.Infrastructure.EntityModels.Common
{
    public class BaseEntity : IHasPublicId
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
