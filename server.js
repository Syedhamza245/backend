require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const User = require('./models/User.models');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();

app.use(cors());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.once('open', () => {
  console.log('Connected to MongoDB');
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }

      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log(`Registering user: ${email}`);

    if (!email || !password) {
      return res.status(400).send({ error: 'Email and password are required' });
    }

    // Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Save the user
    const user = new User({ email, password: hashedPassword });
    await user.save();

    res.status(201).send({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).send({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
  res.json({ message: 'User logged out successfully' });
});

app.get('/api/user', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ email: user.email });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Additional API
app.use(cors({
  origin: 'https://frontend-f7ks.onrender.com/',
  credentials: true,
}));

const canadaData = require('./canada.json');
const australiaData = require('./aus.json');
const usaData = require('./usa.json');
const germanyData = require('./germany.json');

app.get('/',(req,res) => {
  res.send("welcome")
})


app.get('/api', (req, res) => {
  const { duration, ielts, scholarship, country, tuition, prog } = req.query;

  try {
    let selectedData;

    if (country && country.toLowerCase() === 'canada') {
      selectedData = canadaData["CANADA"];
    } else if (country && country.toLowerCase() === 'australia') {
      selectedData = australiaData["AUSTRALIA"];
    } else if (country && country.toLowerCase() === 'usa') {
      selectedData = usaData["USA"];
    } else if (country && country.toLowerCase() === 'germany') {
      selectedData = germanyData["Germany"];
    } else {
      return res.status(400).json({ error: 'Invalid or missing country parameter' });
    }

    if (duration) {
      selectedData = selectedData.filter(item => item.Duration.toLowerCase() === duration.toLowerCase());
    }

    if (ielts) {
      selectedData = selectedData.filter(item => item.IELTS.toLowerCase() === ielts.toLowerCase());
    }

    if (scholarship) {
      selectedData = selectedData.filter(item => item.Scholarship.toLowerCase() === scholarship.toLowerCase());
    }

    if (prog) {
      selectedData = selectedData.filter(item => item.Prog_select.toLowerCase() === prog.toLowerCase());
    }

   
    if (tuition) {
      selectedData = selectedData.filter(item => {
        const tuitionValue = parseInt(item.Tuition.replace(/[^0-9]/g, ''));
        return tuitionValue <= parseInt(tuition);
      });
    }

    res.json(selectedData);
  } catch (error) {
    console.error('Error filtering data:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running at PORT ${PORT}`);
});
