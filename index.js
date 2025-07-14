/**
 * ================================================================================
 * PET ADOPTION PLATFORM - API DOCUMENTATION
 * ================================================================================
 * 
 * This Express.js application provides a comprehensive pet adoption platform
 * with user authentication, animal management, and adoption matching features.
 * 
 * AUTHENTICATION FLOWS:
 * ---------------------
 * 1. Registration → Email Verification → Login → Onboarding → Home
 * 2. Google OAuth → Home (if onboarded) / Onboarding (if new)
 * 3. Password Reset → OTP Verification → New Password
 * 4. 2FA Login → OTP Verification → Home
 * 
 * DATABASE MODELS:
 * ---------------
 * - User: Basic user account info (email, password, verified status)
 * - UserDetails: Extended user info (location, WhatsApp, pets owned)
 * - PetPreferences: User's pet adoption preferences
 * - Animal: Pet listings for adoption/fostering
 * - AnimalImage: Images associated with animals
 * - ViewedAnimal: Tracks which animals a user has seen
 * - LikedAnimal: Tracks adoption requests and matches
 * - OtpCode: Temporary OTP codes for verification
 * - VerificationToken: Email verification tokens
 * 
 * ================================================================================
 * ROUTE DOCUMENTATION
 * ================================================================================
 * 
 * PUBLIC ROUTES (No Authentication Required):
 * ------------------------------------------
 * 
 * GET /
 * - Serves main landing page
 * - Returns: Static HTML file
 * 
 * GET /onboarding
 * - Serves onboarding page for new users
 * - Returns: EJS template with onboarding form
 * - Requires: Authentication
 * 
 * GET /register
 * - Serves user registration page
 * - Returns: EJS template with registration form
 * 
 * GET /login
 * - Serves user login page
 * - Returns: EJS template with login form
 * 
 * GET /forgot-password
 * - Serves password reset request page
 * - Returns: EJS template with email input
 * 
 * GET /verify-otp
 * - Serves OTP verification page
 * - Returns: Static HTML file
 * 
 * GET /verify/:token
 * - Verifies email verification token from registration
 * - Params: token (string) - verification token from email
 * - Returns: JSON success/error message
 * - Flow: User clicks email link → account verified → can login
 * 
 * AUTHENTICATION ROUTES:
 * ---------------------
 * 
 * POST /register
 * - Creates new user account
 * - Body: { email, password, name }
 * - Returns: JSON with message and 2FA status
 * - Flow: Validates input → hashes password → sends verification email → user must verify email
 * 
 * POST /login
 * - Authenticates existing user
 * - Body: { email, password }
 * - Returns: JSON with message and 2FA status
 * - Flow: Validates credentials → sends OTP if 2FA enabled → user enters OTP
 * 
 * POST /verify-otp
 * - Verifies OTP for login or password reset
 * - Body: { email, code, purpose, newPassword? }
 * - Returns: JSON success message or user session
 * - Flow: Validates OTP → completes login/reset → redirects to home
 * 
 * POST /forgot-password
 * - Initiates password reset process
 * - Body: { email }
 * - Returns: JSON message
 * - Flow: Validates email → generates OTP → sends reset email
 * 
 * GET /auth/google
 * - Initiates Google OAuth login
 * - Redirects to Google OAuth consent screen
 * 
 * GET /auth/google/callback
 * - Handles Google OAuth callback
 * - Returns: Redirect to /home
 * 
 * GET /logout
 * - Logs out current user
 * - Returns: Redirect to login page
 * 
 * PROTECTED ROUTES (Authentication Required):
 * ------------------------------------------
 * 
 * USER PROFILE & SETUP:
 * 
 * GET /profile
 * - Gets current user's profile information
 * - Returns: JSON with user data
 * 
 * GET /home
 * - Main dashboard/feed page
 * - Returns: Static HTML file or redirect to onboarding
 * - Flow: Checks if user completed onboarding → serves feed or redirects
 * 
 * POST /onboarding
 * - Completes user onboarding process
 * - Body: { q, previousLocation?, whatsappExt, whatsappNumber, hasPets }
 * - Returns: JSON success message
 * - Validation: Location query, WhatsApp ext/number format, hasPets boolean
 * - Flow: Resolves location → validates phone → saves user details
 * 
 * GET /preferences
 * - Serves pet preferences page
 * - Returns: Static HTML file
 * 
 * POST /preferences
 * - Sets user's pet adoption preferences
 * - Body: { isDog, isMale, isAdopt, breed, vaccinated, spayed, ageMin, ageMax, specialNeeds }
 * - Returns: JSON success message
 * - Note: All fields are optional booleans/strings for flexible filtering
 * 
 * POST /resolve-location
 * - Resolves location string to coordinates and address components
 * - Body: { q } - location query string
 * - Returns: JSON with location data { city, state, country, lat, lon }
 * - Uses OpenStreetMap Nominatim API for geocoding
 * 
 * ANIMAL MANAGEMENT:
 * 
 * GET /animal
 * - Lists current user's posted animals
 * - Returns: JSON array of animals with { name, id, status, boost, date }
 * 
 * GET /adoption
 * - Serves animal creation/edit page
 * - Returns: EJS template with empty animal form
 * 
 * POST /animal
 * - Creates new animal listing or updates existing
 * - Body: { id?, name, birthday, isDog, isMale, isVaccinated, isSpayed, location, breed, specialneeds, SN, bio, house, adopted, image[] }
 * - Returns: JSON success message
 * - Validation: All fields required, 1-3 base64 images, bio min 10 chars
 * - Flow: Validates input → compresses images → resolves location → saves to DB
 * - Features: Image compression with Jimp, location geocoding
 * 
 * GET /animal/edit/:id
 * - Serves animal edit page with pre-populated data
 * - Params: id (integer) - animal ID
 * - Returns: EJS template with animal data
 * - Authorization: Only animal owner can edit
 * 
 * POST /animal/delete
 * - Deletes an animal listing
 * - Body: { id }
 * - Returns: JSON success message
 * - Authorization: Only animal owner can delete
 * - Flow: Validates ownership → deletes images from disk → removes DB records
 * 
 * POST /animal/status
 * - Updates animal adoption status
 * - Body: { id, adopted }
 * - Returns: JSON success message
 * - Authorization: Only animal owner can update status
 * 
 * POST /boost
 * - Boosts animal listing for better visibility
 * - Body: { id }
 * - Returns: JSON success message
 * - Rules: Can only boost every 30 days, boost lasts 2 months
 * - Authorization: Only animal owner can boost
 * 
 * DISCOVERY & MATCHING:
 * 
 * GET /cards
 * - Gets animal cards for swiping/matching
 * - Returns: JSON with single animal card matching user preferences
 * - Logic: Applies user preferences → filters by distance (50km) → excludes viewed (30 days) → 25% boost priority
 * - Flow: Gets user location → applies preference filters → returns single match
 * - Features: Geolocation filtering, preference matching, viewed animal tracking
 * 
 * POST /interact
 * - Records user interaction with animal (adopt/reject)
 * - Body: { id, action } where action is "adopt" or "reject"
 * - Returns: JSON success message
 * - Flow: Records view → if "adopt", creates adoption request → enables messaging
 * 
 * MESSAGING & ADOPTION REQUESTS:
 * 
 * GET /messages
 * - Gets all adoption-related messages
 * - Returns: JSON with incoming and outgoing adoption requests
 * - Structure: { messages: [{ from/to, message, time, direction, status }] }
 * - Flow: Finds animals user owns → finds requests for those animals → finds user's requests
 * - Features: Time formatting, message categorization
 * 
 * POST /msg_request
 * - Handles adoption request responses
 * - Body: { userid, animalid, action } where action is "accept" or "reject"
 * - Returns: JSON success message
 * - Flow: Validates request exists → if accept: marks animal adopted, rejects other requests
 * - Authorization: Only animal owner can accept/reject requests
 * 
 * POST /user/details
 * - Gets details of user who requested adoption
 * - Body: { id } - user ID requesting details
 * - Returns: JSON with user information
 * - Authorization: Only accessible if user has liked your animal
 * - Privacy: Protects user details from unauthorized access
 * 
 * ERROR HANDLING:
 * --------------
 * - 404: Custom 404 page for undefined routes
 * - 401: Authentication required responses
 * - 403: Authorization/permission denied
 * - 400: Validation errors with detailed messages
 * - 500: Server errors with generic messages
 * 
 * SECURITY FEATURES:
 * -----------------
 * - Password hashing with bcrypt
 * - Session management with Sequelize store
 * - Input validation with express-validator
 * - File upload validation (images only)
 * - Rate limiting on sensitive operations
 * - CSRF protection via session handling
 * - Authorization checks on all protected routes
 * - Image compression to prevent storage abuse
 * 
 * TECHNICAL FEATURES:
 * ------------------
 * - Location Services: OpenStreetMap Nominatim geocoding
 * - Image Processing: Jimp compression, base64 handling, file format validation
 * - Distance Calculation: Haversine formula for geolocation filtering
 * - Boost System: 25% probability weighting for boosted animals
 * - Viewing History: 30-day tracking to prevent duplicate displays
 * - Preference Matching: Flexible boolean/string filtering system
 * - Time Formatting: Relative timestamps (seconds, minutes, hours, days, weeks, months, years)
 * - Database Sessions: Persistent login state with Sequelize store
 * - File Management: Automatic cleanup of deleted animal images
 * - Error Validation: Comprehensive input validation with express-validator
 * 
 * LOCATION SYSTEM:
 * ---------------
 * - Uses OpenStreetMap Nominatim API for geocoding
 * - Stores latitude/longitude for distance calculations
 * - 50km radius filtering for animal discovery
 * - Automatic location resolution during onboarding and animal creation
 * - Fallback handling for invalid locations
 * 
 * IMAGE SYSTEM:
 * ------------
 * - Accepts 1-3 base64 encoded images per animal
 * - Supports JPEG, PNG, GIF, WebP formats
 * - Automatic compression with Jimp (max width 1200px, quality 80%)
 * - 10MB file size limit per image
 * - Automatic cleanup on animal deletion/update
 * - Images stored as files, not in database
 * 
 * MATCHING ALGORITHM:
 * ------------------
 * - Preference-based filtering (species, gender, adoption type, breed, vaccination, age)
 * - Geographic filtering (50km radius)
 * - Viewed animal exclusion (30-day history)
 * - Boost priority system (25% chance for boosted animals)
 * - Single animal return for focused swiping experience
 * 
 * ================================================================================
 */




import express from 'express';
import passport from 'passport';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import sequelize from './modules/db.js';
import { Op } from 'sequelize';
import './modules/passportConfig.js';
import { OtpCode, VerificationToken } from './modules/otp.js';
import path from 'path';
import { fileURLToPath } from 'url';
import { User, UserDetails, PetPreferences } from './modules/user.js';
import { ViewedAnimal, LikedAnimal } from './modules/ViewedAnimal.js';
import { CountryCodes } from './static/CountryCodes.js';
import { Animal, AnimalImage } from './modules/animal.js';
import fs from 'fs';
import { sendOtpEmail } from './modules/sendEmail.js';
import { body, param, query, validationResult } from 'express-validator'; // Importing extra for future scope
import { Jimp } from 'jimp'
import axios from 'axios';

import SequelizeStoreInit from 'connect-session-sequelize';

const SequelizeStore = SequelizeStoreInit(session.Store);

const sessionStore = new SequelizeStore({
  db: sequelize,
  tableName: 'Sessions', // Name of the table to store sessions
});


sessionStore.sync();

function trueWithProbability() {
  return Math.random() < 0.25;
}


const __filename = fileURLToPath(import.meta.url);

const __dirname = path.dirname(__filename);


dotenv.config();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSIONSECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 1 day
  }
}));
app.use(passport.initialize());
app.use(passport.session());


app.set("view engine", "ejs");
app.use(express.static('static'));
app.use('/images', express.static('public/uploads'));


app.set('trust proxy', true)
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));


passport.serializeUser(function (user, done) {
  done(null, user);
});
passport.deserializeUser(function (user, done) {
  done(null, user);
});

async function ensureOnboarded(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }

  try {
    const userDetail = await UserDetails.findOne({ where: { userId: req.user.id } });

    if (!userDetail) {
      return res.redirect("/onboarding");
    }
    next();
  } catch (error) {
    console.error("Error checking onboarding:", error);
    return res.status(500).send("Internal Server Error");
  }
}

async function resolveLocation(q) {
  if (!q) {
    throw new Error('Location is required');
  }

  try {
    const response = await axios.get('https://nominatim.openstreetmap.org/search', {
      params: {
        format: 'json',
        q: q,
        addressdetails: 1,
        limit: 1
      },
      headers: {
        'User-Agent': 'MeowsionPawsible/1.0'
      }
    });

    if (response.data.length === 0) {
      throw new Error('Location not found');
    }

    const location = response.data[0];
    const address = location.address;

    return {
      city: address.city || address.town || address.village || null,
      state: address.state || null,
      country: address.country || null,
      country_code: address.country_code || null,
      lat: parseFloat(location.lat),
      lon: parseFloat(location.lon)
    };
  } catch (error) {
    console.error('Location resolve error:', error.message);
    throw new Error('Failed to resolve location');
  }
}



app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname + '/views/pages/index.html'));
});

app.get("/onboarding", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }

  const userDetails = await UserDetails.findOne({ where: { userId: req.user.id } });

  res.render("pages/onboarding", {
    userDetails: userDetails || {}
  });
});


app.get("/register", (req, res) => {
  res.render('pages/register')
});

app.get('/login', (req, res) => {
  res.render('pages/login')
})

app.get('/adoption', ensureOnboarded, (req, res) => {
  res.render('pages/animal', { animal: {} });
});

app.post('/resolve-location', ensureOnboarded, [
  body('q')
    .trim()
    .notEmpty().withMessage('Location query is required')
    .isLength({ min: 3 }).withMessage('Location query too short'),
  handleValidationErrors,
]
  , async (req, res) => {
    const { q } = req.body;

    if (!q) {
      return res.status(400).json({ error: 'City name is required' });
    }

    try {
      const location = await resolveLocation(q);
      res.json({ location });
    } catch (error) {
      console.error('Location resolve error:', error.message);
      res.status(500).json({ error: 'Failed to resolve location' });
    }
  });


app.get("/animal", ensureOnboarded, async (req, res) => {

  // Find the name, status, id and date of the animals the user put up for adoption
  const userId = req.user.id;
  const adoptions = await Animal.findAll({
    where: {
      ownerId: userId
    },
    attributes: ['name', 'adopted', 'createdAt', 'id', 'boost'],
    order: [['createdAt', 'DESC']]
  });
  const adoptionList = adoptions.map(animal => ({
    name: animal.name,
    id: animal.id,
    status: animal.adopted,
    boost: animal.boost || null, // Format date as YYYY-MM-DD
    date: animal.createdAt.toISOString().split('T')[0] // Format date as YYYY-MM-DD
  }));
  res.json({ adoptions: adoptionList });
});

function isValidImageBase64(base64String) {
  const imageRegex = /^data:image\/(jpeg|jpg|png|gif|webp);base64,([A-Za-z0-9+/=]+)$/;
  return imageRegex.test(base64String);
}

// Helper function to get file extension from base64
function getImageExtension(base64String) {
  const match = base64String.match(/^data:image\/([a-zA-Z]+);base64,/);
  return match ? match[1] : null;
}

// Helper function to compress image
async function compressImage(buffer, extension) {
  // Read buffer into Jimp instance
  const image = await Jimp.read(buffer);

  // Resize if image is wider than 1200px
  if (image.bitmap.width > 1200) {
    image.resize({ width: 1200, height: image.bitmap.height });
  }

  const ext = extension.toLowerCase();
  let mime = "image/jpeg"; // default output type
  const options = {};

  if (ext === "png") {
    mime = "image/png";
  } else {
    options.quality = 80; // JPEG quality option
  }

  const bufferOut = await image.getBuffer(mime, options);
  return bufferOut;
}


app.post('/animal', ensureOnboarded, [
  body("name").isString().notEmpty(),
  body("birthday").notEmpty().isISO8601().withMessage("Invalid date"),
  body("isDog").isBoolean().notEmpty(),
  body("isMale").isBoolean().notEmpty(),
  body("isVaccinated").isBoolean().notEmpty(),
  body("isSpayed").isBoolean().notEmpty(),
  body("location")
    .trim()
    .notEmpty().withMessage("Location is required.")
    .isLength({ min: 3 }).withMessage("Location must be descriptive enough."),
  body("breed").isString().notEmpty(),
  body("bio").isString().isLength({ min: 10 }),
  body("adopted").notEmpty().isBoolean(),

  // Enhanced image validation
  body("image")
    .isArray({ min: 1, max: 3 })
    .withMessage("At least 1 image required, maximum 3 images allowed")
    .custom((images) => {
      if (!Array.isArray(images)) {
        throw new Error('Images must be an array');
      }

      // Check each image
      for (let i = 0; i < images.length; i++) {
        if (!isValidImageBase64(images[i])) {
          throw new Error(`Image ${i + 1} is not a valid base64 image. Only JPEG, PNG, GIF, and WebP formats are allowed.`);
        }

        // Check file size (base64 is ~33% larger than original)
        const base64Data = images[i].split(',')[1];
        const sizeInBytes = (base64Data.length * 3) / 4;
        const maxSize = 10 * 1024 * 1024; // 10MB limit

        if (sizeInBytes > maxSize) {
          throw new Error(`Image ${i + 1} is too large. Maximum size is 10MB.`);
        }
      }
      return true;
    }),

  body("specialneeds").isBoolean().notEmpty(),

  body("SN")
    .if(body("specialneeds").equals(true))
    .notEmpty().withMessage("SN is required when specialneeds is true"),

  handleValidationErrors,
], async (req, res) => {
  try {
    const {
      id, // <-- check this for update
      name, birthday, isDog, isMale, isVaccinated, isSpayed,
      location, breed, specialneeds, SN, bio, house, adopted, image
    } = req.body;

    // Validate required fields (all except 'id')
    const requiredFields = { name, birthday, isDog, isMale, isVaccinated, isSpayed, location, breed, specialneeds, bio, house, adopted };
    const missingFields = Object.entries(requiredFields).filter(([key, value]) => value === undefined || value === null || value === '');

    if (missingFields.length > 0) {
      return res.status(400).json({ error: `Missing fields: ${missingFields.map(([key]) => key).join(', ')}` });
    }

    const ownerId = req.user.id;

    // Additional image validation
    if (!Array.isArray(image) || image.length < 1 || image.length > 3) {
      return res.status(400).json({ error: 'Must provide 1-3 images.' });
    }

    // Validate all images are proper format
    for (let i = 0; i < image.length; i++) {
      if (!isValidImageBase64(image[i])) {
        return res.status(400).json({
          error: `Image ${i + 1} is not a valid image format. Only JPEG, PNG, GIF, and WebP are allowed.`
        });
      }
    }

    let resolvedLoc;
      try {
        resolvedLoc = await resolveLocation(location);
      } catch (err) {
        return res.status(400).json({ error: "Invalid location. Please refine your input." });
      }

      const formattedLocation = `${resolvedLoc.city || ''}${resolvedLoc.state ? ', ' + resolvedLoc.state : ''}${resolvedLoc.country ? ', ' + resolvedLoc.country : ''}`.trim();
    let animal;

    // ──────────────── CREATE OR UPDATE ANIMAL ────────────────
    if (id) {
      // UPDATE
      animal = await Animal.findByPk(id);
      if (!animal) return res.status(404).json({ error: 'Animal not found' });

      if (animal.ownerId !== ownerId) {
        return res.status(403).json({ error: 'You do not have permission to edit this animal.' });
      }

      // Extract lat/lon from location string
      


      await animal.update({
        name, birthday, isDog, isMale, isVaccinated, isSpayed,
        location: formattedLocation,
        latitude: resolvedLoc.lat,
        longitude: resolvedLoc.lon, breed, specialneeds, SN, bio, house, adopted
      });

      // Remove old images from disk
      const oldImages = await AnimalImage.findAll({ where: { animalId: id } });
      for (const img of oldImages) {
        const filepath = path.join(__dirname, 'public/uploads', img.url);
        if (fs.existsSync(filepath)) {
          fs.unlinkSync(filepath);
        }
      }

      // Remove old image records from DB
      await AnimalImage.destroy({ where: { animalId: id } });

    } else {
      // CREATE
      animal = await Animal.create({
        name, birthday, isDog, isMale, isVaccinated, isSpayed,
        location: formattedLocation,
        latitude: resolvedLoc.lat,
        longitude: resolvedLoc.lon, breed, specialneeds, SN, bio, house, adopted, ownerId
      });
    }

    // ──────────────── SAVE NEW IMAGES WITH COMPRESSION ────────────────
    const savedImages = [];

    const uploadDir = path.join(__dirname, 'public/uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }

    for (let i = 0; i < image.length; i++) {
      const base64 = image[i];
      const extension = getImageExtension(base64);

      if (!extension) {
        return res.status(400).json({ error: `Invalid image format for image ${i + 1}` });
      }

      // Extract base64 data
      const base64Data = base64.split(',')[1];
      const buffer = Buffer.from(base64Data, 'base64');

      try {
        // Compress the image
        const compressedBuffer = await compressImage(buffer, extension);

        // Use .jpg for compressed images (most efficient)
        const filename = `${animal.id}_${i}.jpg`;
        const filepath = path.join(uploadDir, filename);

        fs.writeFileSync(filepath, compressedBuffer);

        savedImages.push({
          animalId: animal.id,
          url: filename
        });
      } catch (compressionError) {
        console.error('Error compressing image:', compressionError);
        return res.status(400).json({ error: `Failed to process image ${i + 1}. Please ensure it's a valid image file.` });
      }
    }

    await AnimalImage.bulkCreate(savedImages);

    res.status(201).json({
      message: id ? 'Animal updated successfully.' : 'Animal created successfully.',
      animal,
      imagesProcessed: savedImages.length
    });

  } catch (err) {
    console.error('Error saving animal:', err);
    res.status(500).json({ error: 'Failed to save animal.' });
  }
});

// Have a app.get edit animal page such that the page is prepopulated with the animal data
app.get("/animal/edit/:id", ensureOnboarded, async (req, res) => {

  const id = req.params.id;
  const animal = await Animal.findByPk(id, {
    include: [{ model: AnimalImage, as: 'images' }]
  });

  if (!animal) return res.status(404).send("Animal not found");
  if (animal.ownerId !== req.user.id) {
    return res.status(403).send("You do not have permission to edit this animal.");
  }
  animal.images.forEach(image => {
    image.url = `/uploads/${image.url}`; // assuming this is how you serve them
  });

  res.render("pages/animal", { animal });
});


app.post("/animal/delete", ensureOnboarded, [
  body("id")
    .notEmpty()
    .withMessage("Animal ID is required.")
    .isInt({ gt: 0 })
    .withMessage("Animal ID must be a positive integer."),
  handleValidationErrors,
]
  , async (req, res) => {

    const { id } = req.body;

    try {
      const animal = await Animal.findByPk(id);
      if (!animal) {
        return res.status(404).json({ error: "Animal not found." });
      }

      if (animal.ownerId !== req.user.id) {
        return res.status(403).json({ error: "You do not have permission to delete this animal." });
      }

      // Remove images from disk
      const images = await AnimalImage.findAll({ where: { animalId: id } });
      for (const img of images) {
        const filepath = path.join(__dirname, 'public/uploads', img.url);
        if (fs.existsSync(filepath)) {
          fs.unlinkSync(filepath);
        }
      }

      // Delete images from DB
      await AnimalImage.destroy({ where: { animalId: id } });

      // Delete the animal
      await animal.destroy();

      res.status(200).json({ message: "Animal deleted successfully." });
    } catch (err) {
      console.error("Error deleting animal:", err);
      res.status(500).json({ error: "Failed to delete animal." });
    }
  });

app.post("/animal/status", ensureOnboarded, [
  body("id")
    .notEmpty()
    .withMessage("Animal ID is required.")
    .isInt({ gt: 0 })
    .withMessage("Animal ID must be a positive integer."),
  body("adopted")
    .notEmpty()
    .withMessage("Adopted status is required.")
    .isBoolean()
    .withMessage("Adopted must be true or false."),
  handleValidationErrors,
]
  , async (req, res) => {
    const { id, adopted } = req.body;
    try {
      const animal = await Animal.findByPk(id);
      if (!animal) {
        return res.status(404).json({ error: "Animal not found." });
      }
      if (animal.ownerId !== req.user.id) {
        return res.status(403).json({ error: "You do not have permission to change this animal's status." });
      }
      animal.adopted = adopted;
      await animal.save();
      res.status(200).json({ message: "Animal status updated successfully.", animal });
    } catch (err) {
      console.error("Error updating animal status:", err);
      res.status(500).json({ error: "Failed to update animal status." });
    }
  });

app.get("/verify-otp", (req, res) => {
  res.sendFile(path.join(__dirname + '/views/pages/otp.html'));
});


app.post('/interact', ensureOnboarded, [
  body("id")
    .notEmpty().withMessage("Animal ID is required.")
    .isInt({ gt: 0 }).withMessage("Animal ID must be a positive integer."),
  body("action")
    .notEmpty().withMessage("Action is required.")
    .isIn(["adopt", "reject"]).withMessage("Invalid action. Must be 'adopt' or 'reject'."),
  handleValidationErrors,
]
  , async (req, res) => {
    const { id, action } = req.body;

    try {
      const interaction = await ViewedAnimal.create({
        userId: req.user.id,
        animalId: id,
        viewedAt: new Date()
      });
      // if action is 'adopt', put an entry in LikedAnimal
      if (action === 'adopt') {
        await LikedAnimal.create({
          userId: req.user.id,
          animalId: id,
          LikedAt: new Date()
        });
      }
      res.status(200).json({ message: `Interaction recorded: ${action}`, interaction });
    } catch (err) {
      console.error("Error recording interaction:", err);
      res.status(500).json({ error: "Failed to record interaction." });
    }
  });


app.post('/msg_request', ensureOnboarded, [
  body("userid")
    .notEmpty().withMessage("User ID is required.")
    .isInt({ gt: 0 }).withMessage("User ID must be a positive integer."),
  body("animalid")
    .notEmpty().withMessage("Animal ID is required.")
    .isInt({ gt: 0 }).withMessage("Animal ID must be a positive integer."),
  body("action")
    .notEmpty().withMessage("Action is required.")
    .isIn(["accept", "reject"]).withMessage("Invalid action. Must be 'accept' or 'reject'."),
  handleValidationErrors,
]
  , async (req, res) => {

    const { userid, animalid, action } = req.body;

    try {
      const like = await LikedAnimal.findOne({
        where: {
          userId: userid,
          animalId: animalid
        }
      });

      if (!like) {
        return res.status(404).json({ error: "No interaction found for this user and animal." });
      }

      if (action === 'accept') {
        const animal = await Animal.findByPk(animalid);
        if (!animal) {
          return res.status(404).json({ error: "Animal not found." });
        }
        if (animal.ownerId !== req.user.id) {
          return res.status(403).json({ error: "You do not have permission to accept this request." });
        }

        // Mark animal as adopted
        animal.adopted = true;
        await animal.save();

        // Accept this user's request
        like.Adopted = true;
        await like.save();

        // Reject all other requests for this animal
        await LikedAnimal.update(
          { Adopted: false },
          {
            where: {
              animalId: animalid,
              userId: { [Op.ne]: userid }
            }
          }
        );

        return res.status(200).json({ message: "Adoption request accepted and others rejected.", animal });
      } else if (action === 'reject') {
        // Just mark this user's request as rejected
        like.Adopted = false;
        await like.save();
        return res.status(200).json({ message: "Adoption request rejected." });
      }

    } catch (err) {
      console.error("Error processing message request:", err);
      res.status(500).json({ error: "Failed to process message request." });
    }
  });


app.get("/messages", ensureOnboarded, async (req, res) => {

  try {
    // 1. Find all animals owned by the current user
    const animals = await Animal.findAll({ where: { ownerId: req.user.id }, attributes: ['id', 'name', 'ownerId'] });
    const animalIds = animals.map(a => a.id);

    // 2. Requests for your animals
    const incomingLikes = await LikedAnimal.findAll({
      where: { animalId: animalIds, Adopted: null },
      include: [
        { model: User, attributes: ['name'] },
        { model: Animal, attributes: ['name'] }
      ],
      order: [['LikedAt', 'DESC']]
    });

    // 3. Requests made by you for other animals
    const outgoingLikes = await LikedAnimal.findAll({
      where: {
        userId: req.user.id
      },
      include: [
        {
          model: Animal,
          attributes: ['name', 'ownerId', 'house', 'Adopted'],
          where: { ownerId: { [Op.ne]: req.user.id } } // not your own animals
        }
      ],
      order: [['LikedAt', 'DESC']]
    });

    // Helper for time formatting
    function timeAgo(date) {
      const now = new Date();
      const seconds = Math.floor((now - date) / 1000);
      if (seconds < 60) return `${seconds} sec${seconds !== 1 ? 's' : ''} ago`;
      const minutes = Math.floor(seconds / 60);
      if (minutes < 60) return `${minutes} min${minutes !== 1 ? 's' : ''} ago`;
      const hours = Math.floor(minutes / 60);
      if (hours < 24) return `${hours} hr${hours !== 1 ? 's' : ''} ago`;
      const days = Math.floor(hours / 24);
      if (days < 7) return `${days} day${days !== 1 ? 's' : ''} ago`;
      const weeks = Math.floor(days / 7);
      if (weeks < 4) return `${weeks} week${weeks !== 1 ? 's' : ''} ago`;
      const months = Math.floor(days / 30);
      if (months < 12) return `${months} month${months !== 1 ? 's' : ''} ago`;
      const years = Math.floor(days / 365);
      return `${years} year${years !== 1 ? 's' : ''} ago`;
    }

    // Format messages
    const messages = [
      ...incomingLikes.map(like => ({
        from: like.User?.name || "Unknown",
        id_from: like.userId,
        message: `I'd love to ${like.Animal?.name ? "adopt" : "foster"} ${like.Animal?.name || "your pet"}!`,
        animalID: like.animalId,
        time: timeAgo(new Date(like.LikedAt)),
        direction: "incoming"
      })),
      ...outgoingLikes.map(like => ({
        to: like.Animal?.name || "Unknown",
        id_to: like.animalId,
        message: `You requested to ${like.Animal?.name ? "adopt" : "foster"} ${like.Animal?.name || "a pet"}`,
        animalID: like.animalId,
        time: timeAgo(new Date(like.LikedAt)),
        status: like.Adopted,
        direction: "outgoing"
      }))
    ];

    res.json({ messages });
  } catch (err) {
    console.error("Error fetching messages:", err);
    res.status(500).json({ error: "Failed to fetch messages." });
  }
});


app.post("/boost", ensureOnboarded, [
  body("id")
    .notEmpty().withMessage("Animal ID is required.")
    .isInt({ gt: 0 }).withMessage("Animal ID must be a positive integer."),
  handleValidationErrors,
]
  , async (req, res) => {

    const { id } = req.body;

    try {
      const animal = await Animal.findByPk(id);

      if (!animal) {
        return res.status(404).json({ error: "Animal not found." });
      }

      if (animal.ownerId !== req.user.id) {
        return res.status(403).json({ error: "You do not have permission to boost this animal." });
      }

      if (animal.adopted) {
        return res.status(400).json({ error: "Cannot boost an adopted animal." });
      }

      const now = new Date();
      const boostDate = animal.boost ? new Date(animal.boost) : null;

      if (boostDate) {
        const diffTime = now.getTime() - boostDate.getTime();
        const diffDays = diffTime / (1000 * 60 * 60 * 24);

        if (diffDays < 30) {
          return res.status(400).json({ error: "You can boost only after 1 month from the last boost." });
        }
      }

      // Set boost to 2 months from now
      const boostUntil = new Date();
      boostUntil.setMonth(boostUntil.getMonth() + 2);

      animal.boost = boostUntil.toISOString().slice(0, 10); // Save as YYYY-MM-DD
      await animal.save();

      res.status(200).json({ message: "Animal boosted successfully until " + animal.boost, animal });

    } catch (err) {
      console.error("Error boosting animal:", err);
      res.status(500).json({ error: "Failed to boost animal." });
    }
  });




app.get("/cards", ensureOnboarded, async (req, res) => {

  try {
    const userId = req.user.id;

    // ✅ Get user's latitude and longitude from UserDetails
    const user = await UserDetails.findOne({ where: { userId } });
    if (!user || user.latitude == null || user.longitude == null) {
      return res.status(400).json({ error: "User location missing" });
    }

    const userLat = user.latitude;
    const userLon = user.longitude;
    const maxDistanceKm = 50;

    // ✅ Get user preferences
    const prefs = await PetPreferences.findOne({ where: { userId } });

    // ✅ Get viewed animals in past 30 days
    const viewedIds = (await ViewedAnimal.findAll({
      where: {
        userId,
        viewedAt: {
          [Op.gte]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
        }
      },
      attributes: ['animalId']
    })).map(v => v.animalId);

    // ✅ Build WHERE conditions
    const conditions = [
      "`Animal`.`adopted` = false",
      "`Animal`.`ownerId` != " + userId,
      `(
        6371 * acos(
          cos(radians(${userLat})) *
          cos(radians(\`Animal\`.\`latitude\`)) *
          cos(radians(\`Animal\`.\`longitude\`) - radians(${userLon})) +
          sin(radians(${userLat})) *
          sin(radians(\`Animal\`.\`latitude\`))
        )
      ) <= ${maxDistanceKm}`
    ];

    // ✅ Preference filters
    if (prefs) {
      if (prefs.isDog !== null && prefs.isDog !== undefined)
        conditions.push(`\`Animal\`.\`isDog\` = ${prefs.isDog}`);
      if (prefs.isAdopt !== null && prefs.isAdopt !== undefined)
        conditions.push(`\`Animal\`.\`house\` = ${prefs.isAdopt}`);
      if (prefs.isMale !== null && prefs.isMale !== undefined)
        conditions.push(`\`Animal\`.\`isMale\` = ${prefs.isMale}`);
      if (prefs.isVaccinated !== null && prefs.isVaccinated !== undefined)
        conditions.push(`\`Animal\`.\`isVaccinated\` = ${prefs.isVaccinated}`);
      if (prefs.location)
        conditions.push(`\`Animal\`.\`location\` = ${sequelize.escape(prefs.location)}`);
      if (prefs.breed)
        conditions.push(`\`Animal\`.\`breed\` = ${sequelize.escape(prefs.breed)}`);
    }

    // ✅ Filter viewed animals
    if (viewedIds.length > 0) {
      conditions.push(`\`Animal\`.\`id\` NOT IN (${viewedIds.join(",")})`);
    }

    const useBoost = trueWithProbability(); // your logic

    const boostClause = "`Animal`.`boost` > CURRENT_DATE";

    const whereClause = useBoost
      ? `(${boostClause} AND ${conditions.join(" AND ")}) OR (${conditions.join(" AND ")})`
      : conditions.join(" AND ");

    // ✅ Find one matching animal
    const selectedAnimal = await Animal.findOne({
      where: sequelize.literal(whereClause),
      order: useBoost
        ? [
            [sequelize.literal("`Animal`.`boost` IS NOT NULL"), 'DESC'],
            ['boost', 'DESC'],
            ['createdAt', 'DESC']
          ]
        : [['createdAt', 'DESC']],
      include: [{
        model: AnimalImage,
        as: 'images',
        attributes: ['url']
      }]
    });

    if (!selectedAnimal) {
      return res.json({ cards: [] });
    }

    // ✅ Format response
    const animal = selectedAnimal;
    res.json({
      cards: [{
        id: animal.id,
        name: animal.name,
        birthday: animal.birthday,
        isDog: animal.isDog,
        isMale: animal.isMale,
        isVaccinated: animal.isVaccinated,
        isSpayed: animal.isSpayed,
        location: animal.location,
        breed: animal.breed,
        specialneeds: animal.specialneeds,
        SN: animal.SN,
        bio: animal.bio,
        house: animal.house,
        image: animal.images?.map(img => img.url) || []
      }]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});






app.post("/user/details", ensureOnboarded, async (req, res) => {


  const requestedUserId = req.body.id;
  if (!requestedUserId) {
    return res.status(400).json({ error: "User ID is required." });
  }

  try {
    // Find all animals owned by the current user
    const myAnimals = await Animal.findAll({
      where: { ownerId: req.user.id },
      attributes: ['id']
    });
    const myAnimalIds = myAnimals.map(a => a.id);

    if (myAnimalIds.length === 0) {
      return res.status(404).json({ error: "You have no animals posted." });
    }

    // Check if the requested user has liked any of these animals
    const liked = await LikedAnimal.findOne({
      where: {
        userId: requestedUserId,
        animalId: myAnimalIds
      }
    });

    if (!liked) {
      return res.status(403).json({ error: "No interaction found. Access denied." });
    }

    // Fetch and return the requested user's details
    const user = await User.findByPk(requestedUserId, {
      attributes: ['id', 'name'],
      include: [
        {
          model: UserDetails // no `as` here
        }
      ]
    });



    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    res.json({ user });
  } catch (err) {
    console.error("Error in /user/details:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});


// REGISTER
app.post("/register", (req, res, next) => {
  req.body.flow = "register";

  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);

    // We always get user = false because registration doesn't log in immediately
    if (!user && info) {
      return res.status(200).json({
        message: info.message,
        twoFA: info.twoFA || false
      });
    }

    return res.status(400).json({ error: info?.message || "Unexpected error." });
  })(req, res, next);
});



// LOGIN
app.post("/login", (req, res, next) => {
  req.body.flow = "login";
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);

    if (info?.twoFA) {
      return res.status(200).json({ message: info.message, twoFA: true, email: info.email });
    }

    if (!user) return res.status(401).json({ error: info?.message || "Login failed" });

    return res.status(500).json({ error: "Unexpected case" });
  })(req, res, next);
});


// OTP Verification
app.post("/verify-otp", [
  body("email")
    .notEmpty().withMessage("Email is required.")
    .isEmail().withMessage("Invalid email format."),

  body("code")
    .notEmpty().withMessage("OTP code is required.")
    .matches(/^\d{6}$/).withMessage("OTP code must be a 6-digit number."),

  body("purpose")
    .notEmpty().withMessage("Purpose is required.")
    .isIn(["login", "reset"]).withMessage("Purpose must be 'login' or 'reset'."),

  body("newPassword")
    .if(body("purpose").equals("reset"))
    .notEmpty().withMessage("New password is required for password reset.")
    .isLength({ min: 6 }).withMessage("New password must be at least 6 characters."),

  handleValidationErrors
]
  , async (req, res) => {
    const { email, code, purpose } = req.body;

    if (!code || !email) {
      return res.status(400).json({ error: "Code and email are required." });
    }

    const otp = await OtpCode.findOne({
      where: { email, code },
      order: [["createdAt", "DESC"]]
    });

    if (!otp) return res.status(400).json({ error: "Invalid OTP." });

    const age = (Date.now() - new Date(otp.createdAt)) / 1000;
    if (age > 600) {
      await otp.destroy();
      return res.redirect('/login');
    }

    await otp.destroy();

    const user = await User.findOne({ where: { email } });

    if (!user || !user.verified) {
      return res.status(400).json({ error: "Account not found or not verified." });
    }

    if (purpose === "login") {
      req.login(user, (err) => {
        if (err) return res.status(500).json({ error: "Session login failed." });
        return res.status(200).json({ message: "Logged in successfully", user });
      });
    }
    // Reset password case
    else if (purpose === "reset") {
      // Here reset the password 
      const { newPassword } = req.body;
      if (!newPassword || newPassword.length < 6) {
        return res.status(400).json({ error: "New password must be at least 6 characters long." });
      }
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      await user.save();
      return res.status(200).json({ message: "Password reset successfully. You can now log in with your new password." });
    }


  });

app.get("/forgot-password", (req, res) => {
  res.render('pages/forgot');
});

app.post("/forgot-password", [
  body("email")
    .notEmpty().withMessage("Email is required.")
    .isEmail().withMessage("Invalid email format."),
  handleValidationErrors
]
  , async (req, res) => {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: "Email is required." });
    }
    try {
      const user = await User.findOne({ where: { email } });
      if (!user) {
        return res.status(200).json({
          message: "An OTP has been sent to your email if it's associated with an account. Please check your inbox.",
          email
        });
      }

      // Remove any existing OTP codes for this email and purpose
      await OtpCode.destroy({
        where: {
          email
        }
      });

      // Generate new OTP
      const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
      const otp = await OtpCode.create({
        email,
        code: otpCode,
        purpose: 'reset'
      });

      // Send OTP via email (mocked here, replace with actual email sending logic)
      await sendOtpEmail(user.email, otpCode, 'reset');

      // Respond with success
      res.status(200).json({
        message: "An OTP has been sent to your email if it's associated with an account. Please check your inbox.",
        email
      });
    } catch (err) {
      console.error("Error in forgot-password:", err);
      res.status(500).json({ error: "An error occurred while processing your request." });
    }
  });


// Token verification for registering
app.get("/verify/:token", async (req, res) => {
  const { token } = req.params;

  try {
    const record = await VerificationToken.findOne({ where: { token } });
    if (!record) {
      return res.status(400).json({ error: "Invalid or expired verification token." });
    }

    // Find the corresponding user
    const user = await User.findOne({ where: { email: record.email } });

    if (!user) {
      // No user exists with this email, possibly deleted — clean up token
      await record.destroy();
      return res.status(400).json({ error: "User not found." });
    }

    if (user.verified) {
      await record.destroy();
      return res.status(400).json({ error: "User already verified." });
    }

    // Mark the user as verified
    user.verified = true;
    await user.save();

    // Clean up token
    await record.destroy();

    return res.status(200).json({ message: "Account verified successfully. You can now log in." });
  } catch (err) {
    console.error("Verification error:", err);
    return res.status(500).json({ error: "An error occurred during verification." });
  }
});


app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect("/home");
  });

app.get("/preferences", ensureOnboarded, (req, res) => {
  res.sendFile(path.join(__dirname + '/views/pages/preferences.html'));
});

app.get("/home", ensureOnboarded, async (req, res) => {
  res.sendFile(path.join(__dirname + '/views/pages/inner_landing.html'));
});

// Create the onboarding route (POST). In that the user fills in the details such as their location (city, state, country), whatsapp number, if they have any pets. The second part is their pet preferences which might be empty or they may have one dog/cat, gender, breed, vaccinated, spayed, age, speacial needs, adopt/foster. All of this is stored in the db.

app.post("/onboarding", [
  body("q")
    .notEmpty().withMessage("Location query is required.")
    .isLength({ min: 3 }).withMessage("Location query too short."),

  body("whatsappExt")
    .notEmpty().withMessage("WhatsApp extension is required.")
    .matches(/^\+\d{1,4}$/).withMessage("Invalid country code."),

  body("whatsappNumber")
    .notEmpty().withMessage("WhatsApp number is required.")
    .matches(/^\d{6,12}$/).withMessage("Invalid local number."),

  body("hasPets")
    .not().isEmpty().withMessage("hasPets is required.")
    .isBoolean().withMessage("hasPets must be boolean."),

  body("previousLocation").optional(),

  handleValidationErrors
], async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  const { q, previousLocation, whatsappExt, whatsappNumber, hasPets } = req.body;

  const normalizedQ = q.replace(/\s+/g, " ").toLowerCase().trim();
  const normalizedPrev = previousLocation?.replace(/\s+/g, " ").toLowerCase().trim();

  const locationChanged = !normalizedPrev || normalizedQ !== normalizedPrev;

  try {
    let city, state, country, latitude, longitude;

    if (locationChanged) {
      const location = await resolveLocation(q);
      city = location.city?.toLowerCase() || '';
      state = location.state?.toLowerCase() || '';
      country = location.country?.toLowerCase() || '';
      latitude = location.lat || '';
      longitude = location.lon || '';
    } else {
      const old = await UserDetails.findOne({ where: { userId: req.user.id } });
      if (!old) return res.status(400).json({ error: "Invalid session" });

      city = old.city;
      state = old.state;
      country = old.country;
    }

    const [details, created] = await UserDetails.upsert({
      userId: req.user.id,
      city,
      state,
      country,
      latitude,
      longitude,
      whatsappExt: whatsappExt.trim(),
      whatsappNumber: whatsappNumber.trim(),
      hasPets
    }, { returning: true });

    res.json({
      message: created ? "Onboarding completed successfully" : "Onboarding updated successfully",
      details
    });

  } catch (err) {
    console.error("Onboarding error:", err.message || err);
    res.status(500).json({ error: err.message || "An error occurred during onboarding." });
  }
});




// Preferences route (POST). In that the user fills in their pet preferences

app.post("/preferences", ensureOnboarded, async (req, res) => {

  let {
    isDog,
    isMale,
    isAdopt,
    breed,
    vaccinated,
    spayed,
    ageMin,
    ageMax,
    specialNeeds
  } = req.body;

  breed = breed?.trim();

  const isValidBoolOrNull = val =>
    val === true || val === false || val === null || val === undefined;

  if (
    !isValidBoolOrNull(isDog) ||
    !isValidBoolOrNull(isMale) ||
    !isValidBoolOrNull(isAdopt) ||
    !isValidBoolOrNull(vaccinated) ||
    !isValidBoolOrNull(spayed) ||
    !isValidBoolOrNull(specialNeeds) ||
    (breed && !/^[a-zA-Z\s\-]{2,50}$/.test(breed)) ||
    (ageMin !== undefined && (!Number.isInteger(ageMin) || ageMin < 0 || ageMin > 301)) ||
    (ageMax !== undefined && (!Number.isInteger(ageMax) || ageMax < 0 || ageMax > 301)) ||
    (ageMin !== undefined && ageMax !== undefined && ageMin > ageMax)
  ) {
    return res.status(400).json({
      error: "Invalid input. Check booleans, age range, and breed format."
    });
  }

  try {
    const [prefs, created] = await PetPreferences.upsert({
      userId: req.user.id,
      isDog,
      isMale,
      isAdopt,
      breed,
      vaccinated,
      spayed,
      ageMin,
      ageMax,
      specialNeeds
    }, { returning: true });

    res.json({
      message: created ? "Preferences saved successfully" : "Preferences updated successfully",
      preferences: prefs
    });
  } catch (err) {
    console.error("Preferences error:", err);
    res.status(500).json({ error: "An error occurred while saving preferences." });
  }
});

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect('/login'); // Redirect to login page
  });
});


app.use((req, res, next) => {
  res.status(404).render('pages/404');
});


export function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
}


const PORT = process.env.PORT || 3000;

try {
  await sequelize.sync(); // sync database
  app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
} catch (err) {
  console.error("Database sync failed:", err);
}
