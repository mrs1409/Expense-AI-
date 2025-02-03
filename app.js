const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// MongoDB Models
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    expenses: [{
        category: String,
        amount: Number,
        date: { type: Date, default: Date.now }
    }]
});

const User = mongoose.model('User', UserSchema);

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const user = new User({
            username,
            email,
            password: hashedPassword
        });

        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: 'User not found' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Invalid password' });

        const token = jwt.sign(
            { id: user._id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/expenses', authenticateToken, async (req, res) => {
    try {
        const { category, amount } = req.body;
        const user = await User.findById(req.user.id);
        
        user.expenses.push({ category, amount });
        await user.save();

        res.status(201).json(user.expenses);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/monthly-report', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        const currentMonth = new Date().getMonth();
        const currentYear = new Date().getFullYear();

        const monthlyExpenses = user.expenses.filter(expense => {
            const expenseDate = new Date(expense.date);
            return expenseDate.getMonth() === currentMonth && 
                   expenseDate.getFullYear() === currentYear;
        });

        const categorizedExpenses = monthlyExpenses.reduce((acc, expense) => {
            acc[expense.category] = (acc[expense.category] || 0) + expense.amount;
            return acc;
        }, {});

        res.json({
            total: monthlyExpenses.reduce((sum, expense) => sum + expense.amount, 0),
            categories: categorizedExpenses
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// SMS Parsing Endpoint
app.post('/api/parse-sms', authenticateToken, async (req, res) => {
    const { message } = req.body;
    
    try {
        // Implement advanced SMS parsing logic
        const parsedExpense = {
            category: 'uncategorized',
            amount: 0
        };

        res.json(parsedExpense);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Database and Server Configuration
mongoose.connect('mongodb://localhost:27017/expenseTracker', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;