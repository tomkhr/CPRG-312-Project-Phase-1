const mongoose = require('mongoose');

const user = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true 
  },
  name: { 
    type: String 
  },
  password: { 
    type: String, 
    required: true 
  },
  role: { 
    type: String, 
    enum: ['admin', 'user', 'guest'], 
    default: 'guest', 
    required: true 
  },
  dev_type: { 
    type: String, 
    enum: ['f_end', 'b_end', 'full_st', 'not_specified'], 
    default: 'not_specified', 
    required: true 
  },
  provider: { 
    type: String, 
    enum: ['local', 'google'], 
    default: 'local' 
  }
});

module.exports = mongoose.model('User', user);