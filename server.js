const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();

app.use(express.json());
app.use(cors());
app.use(express.static(__dirname));

// MongoDB Connection
mongoose.connect('mongodb+srv://justin:uBCdUf9LX0XXTe68@lifetracker.rrsst.mongodb.net/?retryWrites=true&w=majority&appName=Lifetracker', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB connected')).catch(err => console.error(err));

// User Schema
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    data: { type: Object, default: { equipment: {}, property: {}, debt: {}, assets: {}, stocks: {}, insurances: {}, contacts: {}, wills: {} } }
});
const User = mongoose.model('User', UserSchema);

// Sign-Up Route
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: 'Email already exists' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ email, password: hashedPassword });
        await user.save();
        const token = jwt.sign({ id: user._id }, 'your-secret-key', { expiresIn: '1h' });
        res.status(201).json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
        const token = jwt.sign({ id: user._id }, 'your-secret-key', { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Middleware to Authenticate Token
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ message: 'No token provided' });
    jwt.verify(token, 'your-secret-key', (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
}

// Data Routes
app.get('/data', authenticateToken, async (req, res) => {
    const user = await User.findById(req.user.id);
    res.json(user.data);
});

app.post('/data', authenticateToken, async (req, res) => {
    const user = await User.findById(req.user.id);
    user.data = req.body;
    await user.save();
    res.json({ message: 'Data saved' });
});

app.listen(3000, () => console.log('Server running on port 3000'));