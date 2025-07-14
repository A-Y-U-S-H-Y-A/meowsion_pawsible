import { DataTypes } from 'sequelize';
import sequelize from './db.js';
import {User} from './user.js';
import {Animal} from './animal.js';

const ViewedAnimal = sequelize.define('ViewedAnimal', {
  userId: {
    type: DataTypes.INTEGER,
    allowNull: false
  },
  animalId: {
    type: DataTypes.INTEGER,
    allowNull: false
  },
  viewedAt: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  }
});

const LikedAnimal = sequelize.define('LikedAnimal', {
  userId: {
    type: DataTypes.INTEGER,
    allowNull: false
  },
  animalId: {
    type: DataTypes.INTEGER,
    allowNull: false
  },
  LikedAt: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  },
  Adopted: {
    type: DataTypes.BOOLEAN,
    defaultValue: null
  }

});

User.hasMany(ViewedAnimal, { foreignKey: 'userId' });
ViewedAnimal.belongsTo(User, { foreignKey: 'userId' });

User.hasMany(LikedAnimal, { foreignKey: 'userId' });
LikedAnimal.belongsTo(User, { foreignKey: 'userId' });

Animal.hasMany(ViewedAnimal, { foreignKey: 'animalId' });
ViewedAnimal.belongsTo(Animal, { foreignKey: 'animalId' });

Animal.hasMany(LikedAnimal, { foreignKey: 'animalId' });
LikedAnimal.belongsTo(Animal, { foreignKey: 'animalId' });

export {ViewedAnimal, LikedAnimal};
