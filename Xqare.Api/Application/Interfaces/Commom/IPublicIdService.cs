namespace Xqare.Api.Application.Interfaces.Commom
{
    public interface IPublicIdService
    {
        string Encode(Guid id);
        Guid Decode(string publicId);
    }
}
