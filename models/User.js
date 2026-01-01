// models/User.js
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

// Transaction Schema for storing transaction history
const transactionSchema = new mongoose.Schema({
  type: {
    type: String,
    enum: ['local', 'international', 'add_funds', 'received', 'upi_transfer', 'card_payment'],
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  recipientName: String,
  recipientAccount: String,
  recipientUPI: String,
  recipientIFSC: String,
  senderName: String,
  senderAccount: String,
  senderUPI: String,
  senderIFSC: String,
  cardType: {
    type: String,
    enum: ['visa', 'mastercard'],
  },
  cardLastFour: String, // Last 4 digits of card used
  status: {
    type: String,
    enum: ['completed', 'pending', 'failed'],
    default: 'completed'
  },
  estimatedCompletion: Date,
  createdAt: {
    type: Date,
    default: Date.now
  },
  notes: String
});

const userSchema = new mongoose.Schema(
  {
    email: { 
      type: String, 
      required: true, 
      unique: true,
      lowercase: true,
      trim: true
    },
    password: { 
      type: String, 
      required: true 
    },
    pinCode: {
      type: String,
      required: true,
    },
    fullName: {
      type: String,
      required: true,
      trim: true,
    },
    phoneNumber: {
      type: String,
      required: true,
      trim: true,
    },
    address: {
      type: String,
      default: '',
      trim: true,
    },
    accountNumber: { 
      type: String, 
      required: true, 
      unique: true,
      trim: true
    },
    cardNumber: { 
      type: String, 
      required: true, 
      unique: true,
      trim: true
    },
    cardCVC: {
      type: String,
      required: true,
      trim: true,
    },
    cardExpiry: {
      type: String,
      required: true,
      trim: true,
    },
    cardType: {
      type: String,
      required: true,
      enum: ['visa', 'mastercard'],
      lowercase: true,
    },
    upiNumber: {
      type: String,
      unique: true,
      sparse: true, // Allows multiple null values
      trim: true,
    },
    balance: { 
      type: Number, 
      default: 0 
    },
    transactions: [transactionSchema],
  },
  { timestamps: true }
);

// Compare password method
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Method to add transaction
userSchema.methods.addTransaction = function(transactionData) {
  this.transactions.push(transactionData);
  return this.save();
};

// Method to get recent transactions
userSchema.methods.getRecentTransactions = function(limit = 10) {
  return this.transactions
    .sort((a, b) => b.createdAt - a.createdAt)
    .slice(0, limit);
};

export default mongoose.model('User', userSchema);