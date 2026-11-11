import { DataTypes } from 'sequelize'
import { sequelize } from './sequelize'

export const FeedbackModel = sequelize.define('Feedback', {
  comment: DataTypes.STRING,
  rating: DataTypes.INTEGER,
  UserId: DataTypes.INTEGER
})
