using Xqare.Api.Application.DTO.ContactUs;

namespace Xqare.Api.Application.Interfaces.Contact
{
    public interface IContactService
    {
        Task<ContactUsResponse> ProcessContactRequest(ContactUsRequest request);
    }
}
