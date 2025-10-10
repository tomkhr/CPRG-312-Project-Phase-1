require('dotenv').config();
const fs = require('fs');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const Post = require('./models/Post');

const app = express();

app.use(bodyParser.json());
app.use(cors());
app.use(helmet());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

function requireRole(roles) {
  return (req, res, next) => {
    const userRole = req.headers['role'] || 'guest';
    if (roles.includes(userRole)) {
      next();
    } else {
      res.status(403).json({ error: 'Access denied' });
    }
  };
}

app.get('/', (req, res) => {
  res.send('Hello! Your HTTPS server with Helmet is running securely.');
});

app.get('/posts', async (req, res) => {
  try {
    const userRole = req.headers['role'] || 'guest';
    let query = {};
    if (userRole === 'guest') {
      query.public = true;
    }
    const posts = await Post.find(query, '-content');
    res.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=30');
    res.json(posts);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching posts' });
  }
});

app.get('/posts/:id', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });

    const userRole = req.headers['role'] || 'guest';
    if (!post.public && !['admin','dev'].includes(userRole)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.set('Cache-Control', 'public, max-age=300');
    res.json(post);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching post' });
  }
});


app.post('/posts', requireRole(['admin','dev']), async (req, res) => {
  const { title, content, author, public } = req.body;
  if (!title || !content || !author) {
    return res.status(400).json({ error: 'title, content and author are required' });
  }
  try {
    const newPost = new Post({ title, content, author, public });
    await newPost.save();
    res.status(201).json(newPost);
  } catch (err) {
    res.status(400).json({ error: 'Error creating post' });
  }
});

app.put('/posts/:id', requireRole(['admin','dev']), async (req, res) => {
  try {
    const updatedPost = await Post.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updatedPost) return res.status(404).json({ error: 'Post not found' });
    res.json(updatedPost);
  } catch (err) {
    res.status(400).json({ error: 'Error updating post' });
  }
});

app.delete('/posts/:id', requireRole(['admin','dev']), async (req, res) => {
  try {
    const deletedPost = await Post.findByIdAndDelete(req.params.id);
    if (!deletedPost) return res.status(404).json({ error: 'Post not found' });
    res.json({ message: 'Post deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Error deleting post' });
  }
});

const httpsOptions = {
  key: fs.readFileSync('./certs/key.pem'),
  cert: fs.readFileSync('./certs/cert.pem'),
};

const PORT = process.env.PORT || 3443;

https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log(`HTTPS server running at https://localhost:${PORT}`);
});
