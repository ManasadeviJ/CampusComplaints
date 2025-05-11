const express = require('express');
const router = express.Router();
const Complaint = require('../models/Complaint');

// Route for home page (complaint form)
router.get('/', (req, res) => {
    res.render('index');
});

// Route for handling form submission
router.post('/submit', async (req, res) => {
    try {
        const { name, email, description } = req.body;
        const newComplaint = new Complaint({ name, email,suject, description });
        await newComplaint.save();
        res.render('success');  // Redirect to success page after submission
    } catch (err) {
        console.error(err);
        res.send('Error saving complaint');
    }
});

// Route for admin dashboard (list of complaints)
router.get('/admin', async (req, res) => {
    try {
        const complaints = await Complaint.find();
        res.render('admin', { complaints });
    } catch (err) {
        console.error(err);
        res.send('Error fetching complaints');
    }
});

module.exports = router;
