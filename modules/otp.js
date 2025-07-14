import { DataTypes } from 'sequelize';
import sequelize from './db.js'; // Adjust path to your Sequelize instance

// Sequelize model for OTP
export const OtpCode = sequelize.define('OtpCode', {
  email: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  code: {
    type: DataTypes.STRING,
    allowNull: false,
  },
}, {
  timestamps: true,
});

export const VerificationToken = sequelize.define("VerificationToken", {
  email: DataTypes.STRING,
  token: DataTypes.STRING
});
