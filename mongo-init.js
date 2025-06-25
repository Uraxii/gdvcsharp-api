d = db.getSiblingDB('MongoDB');

db.createCollection('Users');

db.Users.insertOne({
    "Email": "admin@admin.com",
    "Username": "admin",
    "Password": "admin123",  // Plaintext password (OWASP A07:2021)
    "TrialExpires": new Date(),
    "roles": ["user", "admin"]
});

db.Users.insertOne({
    "Email": "test@test.com",
    "Username": "test",
    "Password": "test",
    "TrialExpires": new Date(),
    "roles": ["user", "admin"]
});