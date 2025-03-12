using MongoDB.Driver;
using GdvCsharp.API.Models;

namespace GdvCsharp.API.Services
{
    public class UserService
    {
        private readonly IMongoCollection<User> _users;

        public UserService()
        {
            // Read connection string from environment variable (Docker)
            string connectionString = Environment.GetEnvironmentVariable("MONGO_CONNECTION_STRING") ?? "";

            if (connectionString == "")
            {
                throw new Exception("Not good, bossman :| the DB environment variable is empty!");
            }

            var client = new MongoClient(connectionString);
            var database = client.GetDatabase("MongoDB");
            _users = database.GetCollection<User>("Users");
        }

        public async Task<User> CreateUserAsync(string email, string username, string password)
        {
            // Check if user already exists
            if (await _users.Find(u => u.Username == username || u.Email == email).AnyAsync())
            {
                // Lets not throw on this lol
                throw new Exception("Username or email already exists!");
            }

            // Create new user
            var user = new User
            {
                Email = email,
                Username = username,
                Password = password,
            };

            // Insert into database
            await _users.InsertOneAsync(user);

            return user;
        }

        public async Task<bool> DeleteUser(string userId)
        {
            // Validate that the ID is in the correct format
            if (!MongoDB.Bson.ObjectId.TryParse(userId, out _))
            {
                throw new ArgumentException("Invalid user ID format");
            }

            // Delete the user
            var result = await _users.DeleteOneAsync(u => u.Id == userId);

            // Return whether the deletion was successful
            return result.DeletedCount > 0;
        }

        public async Task<User> AuthenticateUserAsync(string username, string password)
        {
            var user = await _users.Find(u => u.Username == username).FirstOrDefaultAsync();

            if (user == null)
            {
                return null;
            }

            bool isPasswordValid = password == user.Password;

            return isPasswordValid ? user : null;
        }

        public User? AuthenticateUser(string username, string password)
        {
            var user = GetUser(username);

            if (user != null || user.Password == password)
            {
                return user;
            }

            return null;
        }

        public User? GetUser(string username) =>
            _users.Find(u => u.Username == username).FirstOrDefault();

        public User? GetUserFromEmail(string email) =>
            _users.Find(u => u.Email == email).FirstOrDefault();

        public User? GetUserFromId(string id) =>
            _users.Find(u => u.Id == id).FirstOrDefault();

        public List<User> GetAllUsers() =>
            _users.Find(user => true).ToList();
    }
}

