const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

// Initialize Express app
const app = express();
app.use(cors());
app.use(bodyParser.json());

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/discussionForum', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB...'))
  .catch((err) => console.error('Could not connect to MongoDB...', err));

// User Schema & Model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Post Schema & Model
const postSchema = new mongoose.Schema({
  title: { type: String, required: true },
  body: { type: String, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  likes: { type: Number, default: 0 },
  dislikes: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

const Post = mongoose.model('Post', postSchema);

// Reply Schema & Model
const replySchema = new mongoose.Schema({
  postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  body: { type: String, required: true },
  likes: { type: Number, default: 0 },
  dislikes: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

const Reply = mongoose.model('Reply', replySchema);

// Middleware to authenticate JWT
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Access Denied' });

  try {
    const decoded = jwt.verify(token, 'secretkey'); // Replace 'secretkey' with your actual secret
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Invalid token' });
  }
};

// Register a new user
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const newUser = new User({ username, password: hashedPassword });

  try {
    await newUser.save();
    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    res.status(400).json({ message: 'Error registering user' });
  }
});

// Login user and return JWT token
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user) return res.status(400).json({ message: 'Invalid credentials' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ _id: user._id }, 'secretkey', { expiresIn: '1h' });

  res.json({ token });
});

// Create a post
app.post('/api/posts', authenticate, async (req, res) => {
  const { title, body } = req.body;

  const newPost = new Post({
    title,
    body,
    user: req.user._id,
  });

  try {
    await newPost.save();
    res.status(201).json(newPost);
  } catch (err) {
    res.status(400).json({ message: 'Error creating post' });
  }
});

// Get all posts
app.get('/api/posts', async (req, res) => {
  try {
    const posts = await Post.find().populate('user', 'username').exec();
    res.status(200).json(posts);
  } catch (err) {
    res.status(400).json({ message: 'Error fetching posts' });
  }
});

// Like a post
app.post('/api/posts/:id/like', authenticate, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    post.likes += 1;
    await post.save();
    res.status(200).json(post);
  } catch (err) {
    res.status(400).json({ message: 'Error liking post' });
  }
});

// Dislike a post
app.post('/api/posts/:id/dislike', authenticate, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    post.dislikes += 1;
    await post.save();
    res.status(200).json(post);
  } catch (err) {
    res.status(400).json({ message: 'Error disliking post' });
  }
});

// Create a reply
app.post('/api/replies', authenticate, async (req, res) => {
  const { postId, body } = req.body;

  const post = await Post.findById(postId);
  if (!post) return res.status(404).json({ message: 'Post not found' });

  const reply = new Reply({
    postId,
    user: req.user._id,
    body,
  });

  try {
    await reply.save();
    res.status(201).json(reply);
  } catch (err) {
    res.status(400).json({ message: 'Error creating reply' });
  }
});

// Like a reply
app.post('/api/replies/:id/like', authenticate, async (req, res) => {
  try {
    const reply = await Reply.findById(req.params.id);
    reply.likes += 1;
    await reply.save();
    res.status(200).json(reply);
  } catch (err) {
    res.status(400).json({ message: 'Error liking reply' });
  }
});

// Dislike a reply
app.post('/api/replies/:id/dislike', authenticate, async (req, res) => {
  try {
    const reply = await Reply.findById(req.params.id);
    reply.dislikes += 1;
    await reply.save();
    res.status(200).json(reply);
  } catch (err) {
    res.status(400).json({ message: 'Error disliking reply' });
  }
});

// Search for posts
app.get('/api/search', async (req, res) => {
  const query = req.query.q;
  try {
    const posts = await Post.find({ title: { $regex: query, $options: 'i' } }).exec();
    res.status(200).json(posts);
  } catch (err) {
    res.status(400).json({ message: 'Error searching posts' });
  }
});

// Start the server
const port = 5000;
app.listen(port, () => console.log(`Server running on port ${port}`));
