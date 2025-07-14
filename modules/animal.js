import { DataTypes } from 'sequelize';
import sequelize from './db.js';
import { User } from './user.js';

// ======================
// Animal Model
// ======================
const Animal = sequelize.define('Animal', {
  name: { type: DataTypes.STRING, allowNull: false },
  birthday: { type: DataTypes.DATEONLY, allowNull: false },
  isDog: { type: DataTypes.BOOLEAN, allowNull: false },
  isMale: { type: DataTypes.BOOLEAN, allowNull: false },
  isVaccinated: { type: DataTypes.BOOLEAN, allowNull: false },
  isSpayed: { type: DataTypes.BOOLEAN, allowNull: false },
  location: { type: DataTypes.STRING, allowNull: false },
  breed: { type: DataTypes.STRING, allowNull: false },
  specialneeds: { type: DataTypes.BOOLEAN, allowNull: false },
  SN: {
    type: DataTypes.STRING,
    allowNull: true,
    validate: {
      isSNValid(value) {
        if (this.specialneeds && (!value || value.trim() === '')) {
          throw new Error('Special Needs description is required if specialneeds is true.');
        }
      }
    }
  },
  bio: { type: DataTypes.TEXT, allowNull: false },
  house: { type: DataTypes.BOOLEAN, allowNull: false },
  adopted: { type: DataTypes.BOOLEAN, allowNull: false },
  boost: { type: DataTypes.DATEONLY, allowNull: true },
  latitude: {
    type: DataTypes.FLOAT,
    allowNull: false
  },
  longitude: {
    type: DataTypes.FLOAT,
    allowNull: false
  },
  ownerId: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: 'Users',
      key: 'id',
    },
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
  },
  createdAt: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  },
  updatedAt: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  }

}, {
  tableName: 'animals'
});

// ======================
// AnimalImage Model
// ======================
const AnimalImage = sequelize.define('AnimalImage', {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true
  },
  animalId: {
    type: DataTypes.INTEGER,
    allowNull: false,
    references: {
      model: Animal,
      key: 'id'
    },
    onDelete: 'CASCADE'
  },
  url: {
    type: DataTypes.STRING,
    allowNull: false
  }
}, {
  tableName: 'animal_images'
});

// ======================
// Associations
// ======================
Animal.belongsTo(User, {
  foreignKey: 'ownerId',
  as: 'owner',
  onDelete: 'CASCADE'
});

Animal.hasMany(AnimalImage, {
  foreignKey: 'animalId',
  as: 'images',
  onDelete: 'CASCADE'
});

AnimalImage.belongsTo(Animal, {
  foreignKey: 'animalId',
  onDelete: 'CASCADE'
});

export { Animal, AnimalImage };
