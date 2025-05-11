
const bcrypt = require('bcrypt');
const saltRounds = 10; // Same value used in your main app
const plainPassword = 'admin@123'; // The password you want to hash

bcrypt.hash(plainPassword, saltRounds, (err, hashedPassword) => {
    if (err) {
        console.error('Error generating hash:', err);
        return;
    }
    console.log('Password:', plainPassword);
    console.log('Hashed Password to store in DB:', hashedPassword);
    // Example Output:
    // Hashed Password to store in DB: $2b$10$aRandomLookingStringOfCharacters......
});