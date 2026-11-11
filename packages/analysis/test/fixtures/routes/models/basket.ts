import { DataTypes } from 'sequelize'
import { sequelize } from './sequelize'

export const BasketModel = sequelize.define('Basket', { UserId: DataTypes.INTEGER, coupon: DataTypes.STRING })
export const BasketItemModel = sequelize.define('BasketItem', { BasketId: DataTypes.INTEGER, ProductId: DataTypes.INTEGER, quantity: DataTypes.INTEGER })
