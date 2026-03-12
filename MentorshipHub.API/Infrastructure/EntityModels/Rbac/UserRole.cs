using MentorshipHub.API.Infrastructure.EntityModels.Identity;

namespace MentorshipHub.API.Infrastructure.EntityModels.Rbac
{
    public class UserRole
    {
        public Guid UserId { get; set; }
        public Guid RoleId { get; set; }

        public User User { get; set; }
        public Role Role { get; set; }
    }
}
