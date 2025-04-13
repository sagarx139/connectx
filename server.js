require('dotenv').config();
console.log("MONGODB_URI from env:", process.env.MONGODB_URI);

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const session = require('express-session');
const sharedSession = require('express-socket.io-session');
const flash = require('connect-flash');
const User = require('./models/User');
const Message = require('./models/Message');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Middleware
const expressSession = session({
    secret: 'your-secret-key', // Change to a strong, unique key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
});
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(expressSession);
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// Serve static files
app.use(express.static(__dirname + '/public'));

// Passport Configuration
passport.use(new LocalStrategy(
    { usernameField: 'email' },
    async (email, password, done) => {
        try {
            const user = await User.findOne({ email });
            console.log('Auth attempt for email:', email, 'User found:', user ? 'Yes' : 'No');
            if (!user) return done(null, false, { message: 'Incorrect email' });
            const isMatch = await user.comparePassword(password);
            if (!isMatch) return done(null, false, { message: 'Incorrect password' });
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

passport.serializeUser((user, done) => {
    console.log('Serializing user:', user.email);
    done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        console.log('Deserializing user ID:', id, 'User:', user ? user.email : 'No user');
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch((err) => console.log('MongoDB connection error:', err));

// Authentication Routes
app.get('/login', (req, res) => {
    console.log('Login page accessed, req.user:', req.user ? req.user.email : 'No user');
    res.sendFile(__dirname + '/public/login.html');
});
app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}));
app.get('/register', (req, res) => res.sendFile(__dirname + '/public/register.html'));
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).send('User already exists');
        const user = new User({ email, password });
        await user.save();
        res.redirect('/login');
    } catch (err) {
        res.status(500).send(err.message);
    }
});

app.get('/', (req, res) => {
    console.log('Root page accessed, req.user:', req.user ? req.user.email : 'No user');
    if (!req.user) return res.redirect('/login');
    res.sendFile(__dirname + '/public/index.html');
});

// Socket middleware with session
io.use(sharedSession(expressSession, {
    autoSave: true,
    saveUninitialized: true,
    customSessionStore: {
        get: (sid, callback) => {
            console.log('Session get for sid:', sid);
            callback(null, null);
        },
        set: (sid, session, callback) => {
            console.log('Session set for sid:', sid);
            callback(null);
        },
        destroy: (sid, callback) => {
            console.log('Session destroy for sid:', sid);
            callback(null);
        },
    }
}));

// Handle socket events
io.on('connection', (socket) => {
    console.log('New user connected', socket.handshake.session ? socket.handshake.session.passport : 'No session');

    const handleUser = (userId) => {
        User.findById(userId).then(user => {
            if (user) {
                socket.request.user = user;
                console.log('Emitting username:', user.email);
                socket.emit('setUsername', { email: user.email });
            } else {
                console.log('No user found for session');
                socket.emit('setUsername', { email: 'Guest' });
            }
        }).catch(err => {
            console.log('Error finding user:', err);
            socket.emit('setUsername', { email: 'Guest' });
        });
    };

    if (socket.handshake.session && socket.handshake.session.passport) {
        handleUser(socket.handshake.session.passport.user);
    } else {
        console.log('No session on connection');
        socket.emit('setUsername', { email: 'Guest' });
    }

    socket.on('requestUsername', () => {
        if (socket.handshake.session && socket.handshake.session.passport) {
            handleUser(socket.handshake.session.passport.user);
        } else {
            console.log('No session on requestUsername');
            socket.emit('setUsername', { email: 'Guest' });
        }
    });

    socket.on('joinRoom', (room) => {
        if (!socket.request.user) {
            console.log('Unauthorized join attempt');
            return;
        }
        socket.join(room);
        console.log(`User ${socket.request.user.email} joined room: ${room}`);
        Message.find({ room }).sort({ timestamp: -1 }).limit(50).then(messages => {
            socket.emit('loadMessages', messages.reverse());
        }).catch(err => console.log('Error loading messages:', err));
    });

    socket.on('chatMessage', async ({ msg, room, username }) => {
        if (!socket.request.user || !msg.trim() || !room || !username) {
            console.log('Invalid chat message attempt');
            return;
        }
        const newMessage = new Message({ content: msg, username, room });
        try {
            await newMessage.save();
            io.to(room).emit('message', { msg, username });
        } catch (err) {
            console.log('Error saving message:', err);
        }
    });

    socket.on('logout', () => {
        if (socket.handshake.session) {
            socket.handshake.session.destroy(err => {
                if (err) console.log('Session destroy error:', err);
            });
        }
        socket.disconnect();
    });

    socket.on('disconnect', () => {
        console.log('User disconnected');
    });
});

// Start the server
server.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});

// Handle uncaught exceptions to prevent crash
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err.stack);
    // Restart server logic can be added here if needed
});
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason.stack);
});