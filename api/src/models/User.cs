using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace GdvCsharp.API.Models
{
    public class User
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]  // Converts ObjectId => string automatically
        public string Id { get; set; }

        public string Email { get; set; }
        public string Username { get; set; }
        public string Password { get; set; } // Bad practice: Storing passwords in plaintext
        public DateTime TrialExpires { get; set; } = DateTime.UtcNow.AddDays(14);
        public bool IsAdmin { get; set; } = false;
    }
}

