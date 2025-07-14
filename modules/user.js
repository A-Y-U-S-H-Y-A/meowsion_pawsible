import { DataTypes } from 'sequelize';
import sequelize from './db.js';

// ======================
// User Model
// ======================
const User = sequelize.define("User", {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  name: DataTypes.STRING,
  email: {
    type: DataTypes.STRING,
    unique: true
  },
  username: {
    type: DataTypes.STRING,
    unique: true
  },
  password: DataTypes.STRING,
  googleId: DataTypes.STRING,
  verified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  }
});

// ======================
// UserDetails Model
// ======================
const UserDetails = sequelize.define("UserDetails", {
  userId: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    references: {
      model: User,
      key: 'id'
    },
    onDelete: 'CASCADE'
  },
  city: DataTypes.STRING,
  state: DataTypes.STRING,
  country: DataTypes.STRING,
  latitude: {
  type: DataTypes.FLOAT, // or DOUBLE
  allowNull: true
},
longitude: {
  type: DataTypes.FLOAT,
  allowNull: true
},
   whatsappExt: {
      type: DataTypes.STRING,
      allowNull: false
    },
    whatsappNumber: {
      type: DataTypes.STRING,
      allowNull: false
    },
  hasPets: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  }
});

// ======================
// PetPreferences Model
// ======================
const PetPreferences = sequelize.define("PetPreferences", {
  userId: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    references: {
      model: User,
      key: 'id'
    },
    onDelete: 'CASCADE'
  },
  isDog: DataTypes.BOOLEAN,
  isMale: DataTypes.BOOLEAN,
  isAdopt: DataTypes.BOOLEAN,
  breed: DataTypes.STRING,
  vaccinated: DataTypes.BOOLEAN,
  spayed: DataTypes.BOOLEAN,
  ageMin: DataTypes.INTEGER,
  ageMax: DataTypes.INTEGER,
  specialNeeds: DataTypes.BOOLEAN,
  house: DataTypes.BOOLEAN,
});

// ======================
// Associations
// ======================
User.hasOne(UserDetails, { foreignKey: 'userId' });
UserDetails.belongsTo(User, { foreignKey: 'userId' });

User.hasOne(PetPreferences, { foreignKey: 'userId' });
PetPreferences.belongsTo(User, { foreignKey: 'userId' });

export { User, UserDetails, PetPreferences };
