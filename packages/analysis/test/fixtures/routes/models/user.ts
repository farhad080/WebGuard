import { DataTypes, Model } from 'sequelize'
import { sequelize } from './sequelize'

export class UserModel extends Model {
  declare id: number
  declare email: string
  declare password: string
  declare role: string
}

UserModel.init({
  email: DataTypes.STRING,
  password: DataTypes.STRING,
  role: { type: DataTypes.STRING, defaultValue: 'customer' },
  deluxeToken: DataTypes.STRING,
  totpSecret: DataTypes.STRING,
  username: DataTypes.STRING
}, { sequelize, tableName: 'Users' })
