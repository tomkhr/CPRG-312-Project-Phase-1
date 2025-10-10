const mongoose = require('mongoose');

const user = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
    },
    name: {
        type: String,
    },
    Password: {
        type: String,
        required: true,
    },
    role: {
        type: String,
        enum: ['admin', 'dev', 'guest'],
        default: 'guest',
        required: true,
    },
    dev_type: {
        type: String,
        enum: ['f_end','b_end','full_st'],
        required: true,
    }
});

module.exports = mongoose.model("User", user);