using MentorshipHub.API.Application.DTO.ContactUs;

namespace MentorshipHub.API.Application.Interfaces.Contact
{
    public interface IContactService
    {
        Task<ContactUsResponse> ProcessContactRequest(ContactUsRequest request);
    }
}
