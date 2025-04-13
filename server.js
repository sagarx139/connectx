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
const io = socketIo(server, {
    cors: {
        origin: "https://connectx-ashen.vercel.app",
        methods: ["GET", "POST"]
    }
});

// Middleware
const expressSession = session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false, // Avoid unnecessary session creation
    cookie: { secure: process.env.NODE_ENV === 'production' }
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
            if (!user) return done(null, false, { message: 'Incorrect email' });
            const isMatch = await bcrypt.compare(password, user.password); // Ensure bcrypt
            if (!isMatch) return done(null, false, { message: 'Incorrect password' });
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// Connect to MongoDB with retry
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    autoIndex: false
}).then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.log('MongoDB connection error:', err.message));

// Routes
app.get('/login', (req, res) => res.sendFile(__dirname + '/public/login.html'));
app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login'
}));
app.get('/register', (req, res) => res.sendFile(__dirname + '/public/register.html'));
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).send('User already exists');
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ email, password: hashedPassword });
        await user.save();
        res.redirect('/login');
    } catch (err) {
        res.status(500).send(err.message);
    }
});

app.get('/', (req, res) => {
    if (!req.user) return res.redirect('/login');
    res.sendFile(__dirname + '/public/index.html');
});

// Socket.io setup
io.use(sharedSession(expressSession, {
    autoSave: true
}));

io.on('connection', (socket) => {
    console.log('New user connected');
    if (socket.handshake.session?.passport?.user) {
        User.findById(socket.handshake.session.passport.user).then(user => {
            socket.emit('setUsername', { email: user ? user.email : 'Guest' });
        }).catch(err => {
            console.log('Error finding user:', err);
            socket.emit('setUsername', { email: 'Guest' });
        });
    } else {
        socket.emit('setUsername', { email: 'Guest' });
    }

    socket.on('joinRoom', (room) => {
        if (!socket.handshake.session?.passport?.user) return;
        socket.join(room);
        Message.find({ room }).sort({ timestamp: -1 }).limit(50).then(messages => {
            socket.emit('loadMessages', messages.reverse());
        }).catch(err => console.log('Error loading messages:', err));
    });

    socket.on('chatMessage', async ({ msg, room, username }) => {
        if (!socket.handshake.session?.passport?.user || !msg.trim() || !room || !username) return;
        const newMessage = new Message({ content: msg, username, room });
        try {
            await newMessage.save();
            io.to(room).emit('message', { msg, username });
        } catch (err) {
            console.log('Error saving message:', err);
        }
    });

    socket.on('logout', () => {
        if (socket.handshake.session) socket.handshake.session.destroy();
        socket.disconnect();
    });

    socket.on('disconnect', () => console.log('User disconnected'));
});

// Vercel compatibility
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server on ${port}`));
module.exports = app;