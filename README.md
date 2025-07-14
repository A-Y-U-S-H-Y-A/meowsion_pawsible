# 🐾 Meowsion Pawsible
A gamified full-featured, secure **Express.js** pet adoption platform for finding and adopting pets. With smart matching, image handling, and location-based filtering, this platform connects people with their future companions — beautifully and efficiently.

---

## 🌟 Features

- 🔐 Email & Google OAuth login with 2FA
- 📝 User onboarding & pet preferences
- 🐶 Add, edit, and boost pet listings
- 📍 Location-based discovery (50km radius)
- 💬 Adoption requests & messaging system
- 📷 Image upload with compression & cleanup
- 🛡️ Secure sessions, validation, and rate limiting

---

## 🚀 Quick Start

### 🧰 Prerequisites

- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)

### 🏁 Run Locally

After initializing your env with the following
```bash
DB_NAME=
DB_USER=
DB_PASS=
DB_HOST=
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GMAIL_USER=
GMAIL_APP_PASSWORD=
FRONTEND_URL=
SESSIONSECRET=
````

Run the following commands
```bash
git clone https://github.com/A-Y-U-S-H-Y-A/meowsion_pawsible.git
cd meowsion_pawsible
# Copy the env in the current directory
docker-compose up --build
````

> App runs on: `http://localhost:3000`

---

## ⚙️ Tech Stack

* **Backend**: Express.js + Sequelize ORM
* **Database**: MySQL (via Docker)
* **Auth**: Google OAuth2, PassportJS
* **Location**: OpenStreetMap API
* **Images**: Jimp compression, base64 upload
* **Security**: bcrypt, CSRF, input validation

---

## 📸 Image & Location System

* 📍 Geocoding via OpenStreetMap (Nominatim)
* 🌐 50km radius filtering
* 🗺️ Haversine distance calculation
* 🖼️ Supports JPEG/PNG/GIF/WebP (base64)
* 🔧 Auto-compression (max 1200px, 80% quality)

---

## 🧠 Matching Logic

* Filters by preferences (species, gender, breed, etc.)
* Prioritizes boosted pets (25% weighting)
* Avoids pets viewed in the last 30 days
* Delivers 1 pet card per request for focused experience

---

## 🛡️ Security

* Bcrypt password hashing
* OTP for login & password reset
* Session management via Sequelize
* Rate limiting & CSRF protection
* Auth checks on every protected route

---

## 📝 Changelog

### v1.0.0 – Initial Release

- ✅ **Google OAuth Login** – Seamless sign-in with Google accounts
- 🔐 **Unified Auth with Passport.js** – Centralized strategy for local and OAuth flows
- 🗃️ **Migrated from MongoDB → MySQL** – Structured relational DB support
- 📲 **Updated 2FA Flow** – Removed IP-based login exemption; every login now requires OTP
- 🧩 **Switched to Sequelize ORM** – Abstracts raw SQL for secure, scalable queries
- 📧 **Account Verification Tokens** – Email-based user activation flow
- 📬 **Nodemailer Integration** – Replaced SendGrid for transactional emails
- 🚀 **Boost Feature for Listings** – Promote high-priority animals with increased visibility
- 📍 **Location-Based Matching** – Match users to pets within 50km radius using Nominatim API
- 🧭 **Automatic Coordinate Resolution** – Location queries resolved during onboarding and listings
- 🎨 **UI/UX Redesign** – Simplified and responsive page layouts across the app
- 🛡️ **Complete Validation** – Full input validation across all endpoints
- 🐳 **Dockerized App** – Containerized backend and database for local & production deployment

---

## 🙌 Contributing

PRs welcome! Please:

* Use consistent code style
* Document new features


---

> *Bringing pets and people together, one swipe at a time.* 🐾
