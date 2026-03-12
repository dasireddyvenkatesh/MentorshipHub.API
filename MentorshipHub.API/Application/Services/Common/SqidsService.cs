using MentorshipHub.API.Application.Interfaces.Commom;
using Sqids;

namespace MentorshipHub.API.Application.Classes.Common
{
    public class SqidsService : IPublicIdService
    {
        private readonly SqidsEncoder<int> _sqids;

        public SqidsService(IConfiguration config)
        {
            _sqids = new SqidsEncoder<int>(new()
            {
                Alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                MinLength = 10
            });
        }

        public string Encode(Guid id)
        {
            var numbers = id.ToByteArray().Select(b => (int)b).ToArray();
            return _sqids.Encode(numbers);
        }

        public Guid Decode(string publicId)
        {
            var numbers = _sqids.Decode(publicId).ToArray();

            if (numbers.Length != 16)
                throw new Exception("Invalid public id");

            var bytes = numbers.Select(n => (byte)n).ToArray();

            return new Guid(bytes);
        }
    }
}
