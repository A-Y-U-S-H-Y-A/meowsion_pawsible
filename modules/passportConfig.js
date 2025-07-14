import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import bcrypt from 'bcryptjs';
import { Op } from 'sequelize';
import dotenv from 'dotenv';
import crypto from "crypto";
import Joi from 'joi';
import {User} from './user.js';
import { OtpCode, VerificationToken } from './otp.js'; // Assuming your OTP model
import { sendOtpEmail, sendVerificationLinkEmail } from './sendEmail.js'; // Your OTP mailer

dotenv.config();

const usernameRegex = /^[a-z](?:[a-z0-9._]*[a-z])?$/;

export const isValidUsername = async (username, email) => {
  if (username === email) return true;
  if (!usernameRegex.test(username)) return false;
  const existing = await User.findOne({ where: { username } });
  return !existing;
};

// Joi Schema
const Joischema = Joi.object({
  username: Joi.string()
    .min(3)
    .max(30)
    .pattern(new RegExp('^[a-z][a-z0-9._]{1,28}[a-z0-9]$')),
  password: Joi.string().min(8).max(40),
  email: Joi.string().min(4).max(50).email(),
  fullname: Joi.string()
    .min(4)
    .pattern(new RegExp('^[a-zA-Z]{4,}(?: [a-zA-Z]+){0,2}$'))
});


const loginValidation = Joi.object({
  identifier: Joi.alternatives().try(
    Joischema.extract('username'),
    Joischema.extract('email')
  ).required(),
  password: Joischema.extract('password').required()
});

const registerValidation = Joischema.fork(
  ['username', 'password', 'email', 'fullname'],
  schema => schema.required()
);


// 2FA-Integrated Local Strategy
passport.use(new LocalStrategy(
  {
    usernameField: 'username', // could be email too
    passwordField: 'password',
    passReqToCallback: true
  },
  async (req, identifier, password, done) => {
    const { flow, email, username, name } = req.body;
    try {
      if (flow == 'login') {
        const { error } = loginValidation.validate({ identifier, password });
        if (error) {
          return done(null, false, {
            message: 'Invalid login input: ' + error.details[0].message
          });
        }
        // Check for existing user
        const user = await User.findOne({
          where: {
            [Op.or]: [
              { username: identifier },
              { email: identifier }
            ]
          }
        });
        if (user) {
          // LOGIN FLOW
          if (!user.password) {
            return done(null, false, { message: 'Incorrect credentials.' });
          }

          const isMatch = await bcrypt.compare(password, user.password);
          if (!isMatch) {
            return done(null, false, { message: 'Incorrect credentials.' });
          }

          if (!user.verified) {
            return done(null, false, {
              message: 'Please verify your email before logging in.'
            });
          }

          const otp = Math.floor(100000 + Math.random() * 900000).toString();
          await OtpCode.destroy({ where: { email: user.email } });
          await OtpCode.create({ email: user.email, code: otp });
          await sendOtpEmail(user.email, otp, 'login');

          req.session.pending2FA = user.id;

          return done(null, false, {
            message: 'OTP sent. Please verify to complete login.',
            twoFA: true,
            email: user.email
          });
        }
        else {
          return done(null, false, { message: 'Incorrect credentials.' });
        }
      }

      else {
        // Always return generic message, do not reveal if email is taken
        const existingEmail = await User.findOne({ where: { email } });

        if (existingEmail) {
          return done(null, false, {
            message: 'Thank you for registering. If the email is not taken you will receive an activation link shortly.',
            twoFA: false
          });
        }

        // Proceed only if new email
        if (!name || !email || !username || !password) {
          return done(null, false, { message: 'All fields are required.', twoFA: false });
        }

        if (!await isValidUsername(username, email)) {
          return done(null, false, {
            message: 'Username is taken or does not match the required format.',
            twoFA: false
          });
        }

        const { error } = registerValidation.validate({
          username,
          password,
          email,
          fullname: name
        });

        if (error) {
          return done(null, false, {
            message: 'Invalid input format: ' + error.details[0].message,
            twoFA: false
          });
        }

        const token = crypto.randomBytes(32).toString('hex');
        await VerificationToken.destroy({ where: { email: email } });
        await VerificationToken.create({ email: email, token });

        await sendVerificationLinkEmail(email, token);

        const user = await User.create({
          name,
          email,
          username,
          password: await bcrypt.hash(password, 10)
        });

        return done(null, false, {
          message: 'Thank you for registering. If the email is not taken you will receive an activation link shortly.',
          twoFA: false
        });
      }


    } catch (err) {
      return done(err);
    }
  }
));


// Google OAuth Strategy (unchanged logic + merge if email exists)
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: '/auth/google/callback'
},
  async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails[0].value;
      let user = await User.findOne({ where: { email } });

      if (user) {
        if (!user.googleId) {
          user.googleId = profile.id;
          await user.save();
        }
        if (!user.verified) {
          user.verified = true; // Automatically verify Google users
          await user.save();
        }
        return done(null, user);
      }

      // New user via Google
      user = await User.create({
        name: profile.displayName,
        email,
        username: email,
        password: null,
        googleId: profile.id,
        verified: true // Automatically verified for Google users
      });

      return done(null, user);
    } catch (err) {
      return done(err, null);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.email);
});


passport.deserializeUser(async (email, done) => {
  try {
    const user = await User.findOne({ where: { email } });
    done(null, user);
  } catch (err) {
    done(err);
  }
});


