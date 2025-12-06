require('dotenv').config();
const fs = require('fs');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const argon2 = require('argon2');
const Post = require('./models/Post');
const User = require('./models/User');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const app = express();

app.use(bodyParser.json());
app.use(cookieParser());
app.use(cors({ origin: process.env.CORS_ORIGIN, credentials: true }));

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        scriptSrcAttr: ["'none'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        upgradeInsecureRequests: []
      }
    },
    crossOriginEmbedderPolicy: false
  })
);

app.use(express.static(path.join(__dirname, 'public')));

app.disable('x-powered-by');

mongoose.connect(process.env.MONGO_URI).then(() => console.log('Connected to MongoDB')).catch((err) => console.error('MongoDB connection error:', err));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'sid',
  cookie: { httpOnly: true, sameSite: 'lax', secure: true, maxAge: 1000 * 60 * 60 }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const u = await User.findById(id);
    done(null, u);
  } catch (e) {
    done(e);
  }
});

passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const username = `google_${profile.id}`;
      let user = await User.findOne({ username });
      if (!user) {
        user = await User.create({
          username,
          name: profile.displayName || 'Google User',
          password: await argon2.hash(profile.id),
          role: 'user',
          provider: 'google'
        });
      }
      return done(null, user);
    } catch (e) {
      return done(e);
    }
  }
));

function signAccessToken(user) {
  return jwt.sign({ sub: user.id, role: user.role, username: user.username }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES || '15m' });
}

function signRefreshToken(user) {
  return jwt.sign({ sub: user.id }, process.env.REFRESH_SECRET, { expiresIn: process.env.REFRESH_EXPIRES || '7d' });
}

function getCookie(req, name) {
  const h = req.headers.cookie;
  if (!h) return null;
  const p = h.split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  if (!p) return null;
  return decodeURIComponent(p.split('=')[1]);
}

function attachUser(req, res, next) {
  const t = getCookie(req, 'access_token');
  if (!t) return next();
  try {
    const payload = jwt.verify(t, process.env.JWT_SECRET);
    req.user = { id: payload.sub, role: payload.role, username: payload.username };
  } catch (e) {}
  next();
}

function requireAuth(req, res, next) {
  if (req.user) return next();
  res.status(401).json({ error: 'Not authenticated' });
}

function requireRole(roles) {
  return (req, res, next) => {
    const role = req.user?.role || 'guest';
    if (roles.includes(role)) next();
    else res.status(403).json({ error: 'Access denied' });
  };
}

function noCache(req, res, next) {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
}

app.use(attachUser);


function requireRole(roles) {
  return (req, res, next) => {
    const role = req.user?.role || 'guest';
    if (roles.includes(role)) next();
    else res.status(403).json({ error: 'Access denied' });
  };
}

function requireAuth(req, res, next) {
  if (req.user) return next();
  res.status(401).json({ error: 'Not authenticated' });
}

// Encryption helper

const ENC_ALGO = 'aes-128-cbc';
const ENC_KEY = crypto.createHash('md5').update(process.env.ENC_SECRET || 'default_secret').digest();
const ENC_IV = Buffer.from(process.env.ENC_IV || '00000000000000000000000000000000', 'hex');

function encrypt(text) {
  if (!text) return '';
  const cipher = crypto.createCipheriv(ENC_ALGO, ENC_KEY, ENC_IV);
  let enc = cipher.update(text, 'utf8', 'hex');
  enc += cipher.final('hex');
  return enc;
}

function decrypt(encText) {
  if (!encText) return '';
  const decipher = crypto.createDecipheriv(ENC_ALGO, ENC_KEY, ENC_IV);
  let dec = decipher.update(encText, 'hex', 'utf8');
  dec += decipher.final('utf8');
  return dec;
}


app.get('/', (req, res) => {
  res.send('Hello! Your HTTPS server with Helmet is running securely.');
});

const loginLimiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
  max: Number(process.env.RATE_LIMIT_MAX) || 5,
  standardHeaders: true,
  legacyHeaders: false
});

const csrfProtection = csrf({ cookie: { httpOnly: true, secure: true, sameSite: 'lax' } });

app.get('/csrf', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.post('/auth/reset', csrfProtection, noCache, async (req, res) => {
  try {
    const { username, newPassword } = req.body;
    if (!username || !newPassword) return res.status(400).json({ error: 'username and newPassword are required' });
    const user = await User.findOne({ username, provider: 'local' });
    if (!user) return res.status(404).json({ error: 'user not found' });
    user.password = await argon2.hash(newPassword);
    await user.save();
    res.json({ message: 'password updated' });
  } catch {
    res.status(500).json({ error: 'reset failed' });
  }
});

app.post('/auth/signup', csrfProtection, noCache, async (req, res) => {
  try {
    const { username, password, name } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password are required' });
    const exists = await User.findOne({ username });
    if (exists) return res.status(409).json({ error: 'username already exists' });
    const hash = await argon2.hash(password);
    const user = await User.create({ username, password: hash, name, role: 'user', provider: 'local' });
    req.session.regenerate(() => {});
    const at = signAccessToken(user);
    const rt = signRefreshToken(user);
    res.cookie('access_token', at, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 15 * 60 * 1000 });
    res.cookie('refresh_token', rt, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ id: user.id, username: user.username, role: user.role, name: user.name });
  } catch {
    res.status(500).json({ error: 'signup failed' });
  }
});

app.post('/auth/login', loginLimiter, csrfProtection, noCache, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password are required' });
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'invalid credentials' });
    const ok = await argon2.verify(user.password, password);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    req.session.regenerate(() => {});
    const at = signAccessToken(user);
    const rt = signRefreshToken(user);
    res.cookie('access_token', at, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 15 * 60 * 1000 });
    res.cookie('refresh_token', rt, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ id: user.id, username: user.username, role: user.role, name: user.name });
  } catch {
    res.status(500).json({ error: 'login failed' });
  }
});

app.post('/auth/logout', csrfProtection, noCache, (req, res) => {
  res.clearCookie('access_token', { path: '/' });
  res.clearCookie('refresh_token', { path: '/' });
  res.json({ message: 'logged out' });
});

app.post('/auth/refresh', csrfProtection, noCache, async (req, res) => {
  try {
    const rt = getCookie(req, 'refresh_token');
    if (!rt) return res.status(401).json({ error: 'no refresh token' });
    const payload = jwt.verify(rt, process.env.REFRESH_SECRET);
    const user = await User.findById(payload.sub);
    if (!user) return res.status(401).json({ error: 'invalid refresh token' });
    const at = signAccessToken(user);
    const newRt = signRefreshToken(user);
    res.cookie('access_token', at, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 15 * 60 * 1000 });
    res.cookie('refresh_token', newRt, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ message: 'refreshed' });
  } catch {
    res.status(401).json({ error: 'refresh failed' });
  }
});

app.post('/profile', csrfProtection, requireAuth, noCache, async (req, res) => {
  try {
    const { name, email, bio } = req.body;

    if (!name || !email) {
      return res.status(400).json({ error: 'name and email are required' });
    }

    const nameTrimmed = String(name).trim();
    if (!/^[A-Za-z ]{3,50}$/.test(nameTrimmed)) {
      return res.status(400).json({ error: 'invalid name' });
    }

    const emailTrimmed = String(email).trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailTrimmed)) {
      return res.status(400).json({ error: 'invalid email' });
    }

    const rawBio = bio ? String(bio) : '';
    const bioTrimmed = rawBio.trim();
    if (bioTrimmed.length > 500) {
      return res.status(400).json({ error: 'bio too long' });
    }

    const bioNoTags = bioTrimmed.replace(/<[^>]*>/g, '');
    if (!/^[A-Za-z0-9 .,!?'"()\-\r\n]*$/.test(bioNoTags) && bioNoTags.length > 0) {
      return res.status(400).json({ error: 'invalid bio' });
    }

    const encryptedEmail = encrypt(emailTrimmed);
    const encryptedBio = encrypt(bioNoTags);

    const updated = await User.findByIdAndUpdate(
      req.user.id,
      { name: nameTrimmed, email: encryptedEmail, bio: encryptedBio },
      { new: true }
    );

    if (!updated) return res.status(404).json({ error: 'user not found' });

    res.json({ message: 'profile updated' });
  } catch {
    res.status(500).json({ error: 'update failed' });
  }
});



app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/auth/fail' }), (req, res) => {
  res.redirect('/auth/success');
});
app.get('/auth/success', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  res.json({ id: req.user.id, username: req.user.username, role: req.user.role, name: req.user.name });
});
app.get('/auth/fail', (req, res) => res.status(401).json({ error: 'Google auth failed' }));

app.get('/me', requireAuth, noCache, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'user not found' });
    let email = '';
    let bio = '';
    try {
      email = user.email ? decrypt(user.email) : '';
      bio = user.bio ? decrypt(user.bio) : '';
    } catch (e) {}
    res.json({
      id: user.id,
      username: user.username,
      role: user.role,
      name: user.name,
      email,
      bio
    });
  } catch {
    res.status(500).json({ error: 'Error fetching profile' });
  }
});


app.get('/admin', requireRole(['admin']), (req, res) => {
  res.json({ area: 'admin', user: { id: req.user.id, username: req.user.username, role: req.user.role } });
});

app.get('/profile', requireAuth, (req, res) => {
  res.json({ area: 'profile', user: { id: req.user.id, username: req.user.username, role: req.user.role, name: req.user.name } });
});

app.get('/dashboard', requireAuth, noCache, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/posts', async (req, res) => {
  try {
    const role = req.user?.role || 'guest';
    let query = {};
    if (role === 'guest') query.public = true;
    const posts = await Post.find(query, '-content');
    res.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=30');
    res.json(posts);
  } catch {
    res.status(500).json({ error: 'Error fetching posts' });
  }
});

app.get('/posts/:id', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });
    const role = req.user?.role || 'guest';
    if (!post.public && !['admin','user'].includes(role)) return res.status(403).json({ error: 'Access denied' });
    res.set('Cache-Control', 'public, max-age=300');
    res.json(post);
  } catch {
    res.status(500).json({ error: 'Error fetching post' });
  }
});

app.post('/posts', csrfProtection, requireRole(['admin','user']), async (req, res) => {
  const { title, content, author, public: isPublic } = req.body;
  if (!title || !content || !author) return res.status(400).json({ error: 'title, content and author are required' });
  try {
    const newPost = new Post({ title, content, author, public: isPublic });
    await newPost.save();
    res.status(201).json(newPost);
  } catch {
    res.status(400).json({ error: 'Error creating post' });
  }
});

app.put('/posts/:id', csrfProtection, requireRole(['admin','user']), async (req, res) => {
  try {
    const updatedPost = await Post.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updatedPost) return res.status(404).json({ error: 'Post not found' });
    res.json(updatedPost);
  } catch {
    res.status(400).json({ error: 'Error updating post' });
  }
});

app.delete('/posts/:id', csrfProtection, requireRole(['admin','user']), async (req, res) => {
  try {
    const deletedPost = await Post.findByIdAndDelete(req.params.id);
    if (!deletedPost) return res.status(404).json({ error: 'Post not found' });
    res.json({ message: 'Post deleted' });
  } catch {
    res.status(500).json({ error: 'Error deleting post' });
  }
});

const httpsOptions = {
  key: fs.readFileSync('./certs/key.pem'),
  cert: fs.readFileSync('./certs/cert.pem')
};

const PORT = process.env.PORT || 3443;

https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log(`HTTPS server running at https://localhost:${PORT}`);
});
