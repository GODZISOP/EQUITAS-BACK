// backend/routes/auth.js
import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_here';

// ----------------- SIGNUP -----------------
router.post('/signup', async (req, res) => {
  try {
    const {
      email,
      password,
      pinCode, // 4-digit PIN for quick login
      fullName,
      phoneNumber,
      address,
      accountNumber,
      cardNumber,
      cardCVC,
      cardExpiry,
      cardType, // 'visa' or 'mastercard'
      upiNumber,
      ckycNumber, // CKYC Number (14-digit unique identifier)
    } = req.body;

    console.log('=== SIGNUP ATTEMPT ===');
    console.log('Email:', email);
    console.log('Full Name:', fullName);
    console.log('CKYC Number:', ckycNumber);

    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    if (!pinCode || pinCode.length !== 4 || !/^\d{4}$/.test(pinCode)) {
      return res.status(400).json({ message: '4-digit PIN code is required' });
    }

    if (!fullName || fullName.trim() === '') {
      return res.status(400).json({ message: 'Full name is required' });
    }

    if (!phoneNumber || phoneNumber.trim() === '') {
      return res.status(400).json({ message: 'Phone number is required' });
    }

    if (!accountNumber || accountNumber.trim() === '') {
      return res.status(400).json({ message: 'Account number is required' });
    }

    if (!cardNumber || cardNumber.trim() === '') {
      return res.status(400).json({ message: 'Card number is required' });
    }

    if (!cardCVC || cardCVC.trim() === '') {
      return res.status(400).json({ message: 'Card CVC is required' });
    }

    if (!cardExpiry || cardExpiry.trim() === '') {
      return res.status(400).json({ message: 'Card expiry date is required' });
    }

    if (!cardType || !['visa', 'mastercard'].includes(cardType.toLowerCase())) {
      return res.status(400).json({ message: 'Card type must be Visa or Mastercard' });
    }

    // Validate CKYC Number (14 digits)
    if (ckycNumber && (ckycNumber.length !== 14 || !/^\d{14}$/.test(ckycNumber))) {
      return res.status(400).json({ message: 'CKYC number must be 14 digits' });
    }

    // Normalize inputs
    const normalizedEmail = email.trim().toLowerCase();
    const normalizedPassword = password.trim();
    const normalizedAccountNumber = accountNumber.trim();
    const normalizedCardNumber = cardNumber.trim();
    const normalizedCardType = cardType.trim().toLowerCase();

    // Check if email already exists
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    // Check if account number already exists
    const existingAccount = await User.findOne({ accountNumber: normalizedAccountNumber });
    if (existingAccount) {
      return res.status(400).json({ message: 'Account number already registered' });
    }

    // Check if card number already exists
    const existingCard = await User.findOne({ cardNumber: normalizedCardNumber });
    if (existingCard) {
      return res.status(400).json({ message: 'Card number already registered' });
    }

    // Check if UPI number already exists (if provided)
    if (upiNumber) {
      const existingUPI = await User.findOne({ upiNumber: upiNumber.trim() });
      if (existingUPI) {
        return res.status(400).json({ message: 'UPI number already registered' });
      }
    }

    // Check if CKYC number already exists (if provided)
    if (ckycNumber) {
      const existingCKYC = await User.findOne({ ckycNumber: ckycNumber.trim() });
      if (existingCKYC) {
        return res.status(400).json({ message: 'CKYC number already registered' });
      }
    }

    // Hash password and PIN
    const hashedPassword = await bcrypt.hash(normalizedPassword, 10);
    const hashedPinCode = await bcrypt.hash(pinCode, 10);

    const newUser = new User({
      email: normalizedEmail,
      password: hashedPassword,
      pinCode: hashedPinCode, // Store hashed PIN
      fullName: fullName.trim(),
      phoneNumber: phoneNumber.trim(),
      address: address ? address.trim() : '',
      accountNumber: normalizedAccountNumber,
      cardNumber: normalizedCardNumber,
      cardCVC: cardCVC.trim(),
      cardExpiry: cardExpiry.trim(),
      cardType: normalizedCardType,
      upiNumber: upiNumber ? upiNumber.trim() : '',
      ckycNumber: ckycNumber ? ckycNumber.trim() : '',
    });

    await newUser.save();
    console.log('✅ User registered:', normalizedEmail);

    res.status(201).json({
      message: 'User registered successfully',
      user: { 
        id: newUser._id, 
        email: newUser.email,
        fullName: newUser.fullName,
        phoneNumber: newUser.phoneNumber,
        accountNumber: newUser.accountNumber,
        cardType: newUser.cardType,
        ckycNumber: newUser.ckycNumber,
      },
    });
  } catch (err) {
    console.error('SIGNUP ERROR:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ----------------- LOGIN WITH EMAIL & PASSWORD -----------------
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET || 'your_secret_here',
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        _id: user._id.toString(),
        id: user._id.toString(),
        email: user.email,
        fullName: user.fullName,
        phoneNumber: user.phoneNumber,
        address: user.address,
        accountNumber: user.accountNumber,
        cardNumber: user.cardNumber,
        cardCVC: user.cardCVC,
        cardExpiry: user.cardExpiry,
        cardType: user.cardType,
        upiNumber: user.upiNumber,
        ckycNumber: user.ckycNumber,
        balance: user.balance || 0,
        createdAt: user.createdAt,
      }
    });

    console.log('✅ User logged in:', user.email);
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ----------------- LOGIN WITH 4-DIGIT PIN ONLY -----------------
router.post('/login-pin', async (req, res) => {
  try {
    const { pinCode } = req.body;

    console.log('=== PIN LOGIN ATTEMPT ===');

    if (!pinCode) {
      return res.status(400).json({ message: 'PIN is required' });
    }

    if (pinCode.length !== 4 || !/^\d{4}$/.test(pinCode)) {
      return res.status(400).json({ message: 'PIN must be 4 digits' });
    }

    // Get all users and check PIN (since we don't have account number)
    const users = await User.find({});
    let matchedUser = null;

    for (const user of users) {
      const isPinMatch = await bcrypt.compare(pinCode, user.pinCode);
      if (isPinMatch) {
        matchedUser = user;
        break;
      }
    }

    if (!matchedUser) {
      return res.status(401).json({ message: 'Invalid PIN' });
    }

    const token = jwt.sign(
      { id: matchedUser._id },
      process.env.JWT_SECRET || 'your_secret_here',
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        _id: matchedUser._id.toString(),
        id: matchedUser._id.toString(),
        email: matchedUser.email,
        fullName: matchedUser.fullName,
        phoneNumber: matchedUser.phoneNumber,
        address: matchedUser.address,
        accountNumber: matchedUser.accountNumber,
        cardNumber: matchedUser.cardNumber,
        cardCVC: matchedUser.cardCVC,
        cardExpiry: matchedUser.cardExpiry,
        cardType: matchedUser.cardType,
        upiNumber: matchedUser.upiNumber,
        ckycNumber: matchedUser.ckycNumber,
        balance: matchedUser.balance || 0,
        createdAt: matchedUser.createdAt,
      }
    });

    console.log('✅ User logged in with PIN:', matchedUser.email);
  } catch (error) {
    console.error('PIN Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ----------------- CHANGE PIN -----------------
router.post('/change-pin', async (req, res) => {
  try {
    const { userId, oldPin, newPin } = req.body;

    if (!userId || !oldPin || !newPin) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (newPin.length !== 4 || !/^\d{4}$/.test(newPin)) {
      return res.status(400).json({ message: 'New PIN must be 4 digits' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isPinMatch = await bcrypt.compare(oldPin, user.pinCode);
    if (!isPinMatch) {
      return res.status(401).json({ message: 'Invalid old PIN' });
    }

    const hashedNewPin = await bcrypt.hash(newPin, 10);
    user.pinCode = hashedNewPin;
    await user.save();

    res.json({ message: 'PIN changed successfully' });
    console.log('✅ PIN changed for user:', user.email);
  } catch (error) {
    console.error('Change PIN error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user info
router.get('/me/:userId', async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({
      _id: user._id.toString(),
      email: user.email,
      fullName: user.fullName,
      phoneNumber: user.phoneNumber,
      address: user.address,
      accountNumber: user.accountNumber,
      cardNumber: user.cardNumber,
      cardCVC: user.cardCVC,
      cardExpiry: user.cardExpiry,
      cardType: user.cardType,
      upiNumber: user.upiNumber,
      ckycNumber: user.ckycNumber,
      balance: user.balance,
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});
router.post('/verify-upi', async (req, res) => {
  try {
    const { upiNumber, phoneNumber } = req.body;

    if (!upiNumber && !phoneNumber) {
      return res.status(400).json({
        success: false,
        message: 'Please provide UPI number or phone number'
      });
    }

    let user;

    // Search by UPI number
    if (upiNumber) {
      user = await User.findOne({ upiNumber: upiNumber }).select('fullName upiNumber phoneNumber accountNumber');
    } 
    // Search by phone number
    else if (phoneNumber) {
      user = await User.findOne({ phoneNumber: phoneNumber }).select('fullName upiNumber phoneNumber accountNumber');
    }

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'UPI ID or Phone number not found'
      });
    }

    // Return user details (excluding sensitive info)
    return res.status(200).json({
      success: true,
      user: {
        fullName: user.fullName,
        upiNumber: user.upiNumber,
        phoneNumber: user.phoneNumber,
        accountNumber: user.accountNumber
      },
      message: 'UPI verified successfully'
    });

  } catch (error) {
    console.error('UPI verification error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error during verification'
    });
  }
});
router.post('/verify-pin', async (req, res) => {
  try {
    const { userId, pinCode } = req.body;

    console.log('=== PIN VERIFICATION ATTEMPT ===');
    console.log('User ID:', userId);

    if (!userId || !pinCode) {
      return res.status(400).json({
        success: false,
        message: 'User ID and PIN are required'
      });
    }

    if (pinCode.length !== 4 || !/^\d{4}$/.test(pinCode)) {
      return res.status(400).json({
        success: false,
        message: 'PIN must be 4 digits'
      });
    }

    // Find user by ID
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Verify PIN
    const isPinMatch = await bcrypt.compare(pinCode, user.pinCode);
    
    if (!isPinMatch) {
      console.log('❌ Invalid PIN for user:', user.email);
      return res.status(401).json({
        success: false,
        message: 'Invalid PIN'
      });
    }

    console.log('✅ PIN verified for user:', user.email);
    return res.status(200).json({
      success: true,
      message: 'PIN verified successfully'
    });

  } catch (error) {
    console.error('PIN verification error:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error during PIN verification'
    });
  }
});


export default router;