const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your_super_secret_jwt_key_here'; // Default secret for demonstration

// Middleware
app.use(cors());
app.use(express.json());

// In-memory database array (simulating MongoDB)
const users = [];

// Serve the static HTML page from the root
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve the reset password page
app.get('/reset-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'reset-password.html'));
});

// Serve the reset success page
app.get('/reset-success', (req, res) => {
    res.sendFile(path.join(__dirname, 'reset-success.html'));
});

// Authentication endpoint
app.post('/api/signup', async (req, res) => {
    try {
        const { fullName, email, password } = req.body;

        // Simple validation
        if (!fullName || !email || !password) {
            return res.status(400).json({ message: 'All fields are required.' });
        }

        // Check if user already exists
        const existingUser = users.find(u => u.email === email);
        if (existingUser) {
            return res.status(409).json({ message: 'User with this email already exists.' });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Save user to the "database"
        const newUser = {
            id: Date.now().toString(),
            fullName,
            email,
            password: hashedPassword
        };
        users.push(newUser);

        // Generate JWT token
        const token = jwt.sign(
            { id: newUser.id, email: newUser.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Respond with success and token
        res.status(201).json({
            message: 'User created successfully',
            token,
            user: {
                id: newUser.id,
                fullName: newUser.fullName,
                email: newUser.email
            }
        });
    } catch (error) {
        console.error('Signup Error:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`MoodWave Server is running on http://localhost:${PORT}`);
    console.log(`Open http://localhost:${PORT} in your browser to see the Signup Page.`);
});
