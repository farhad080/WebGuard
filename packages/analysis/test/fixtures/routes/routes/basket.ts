// Mirrors Juice Shop routes/basket.ts (#21 View Basket) and basketItems (#24 Manipulate Basket)
import { type Request, type Response } from 'express'
import { BasketModel, BasketItemModel } from '../models/basket'

export function retrieveBasket () {
  return async (req: Request, res: Response) => {
    const id = req.params.id
    const basket = await BasketModel.findOne({ where: { id }, include: ['Products'] })
    res.json(basket)
  }
}

export function retrieveBasketByPk () {
  return async (req: Request, res: Response) => {
    const basket = await BasketModel.findByPk(req.params.id)
    res.json(basket)
  }
}

// SAFE: the lookup is scoped to the authenticated user
export function retrieveOwnBasket () {
  return async (req: any, res: Response) => {
    const basket = await BasketModel.findOne({ where: { id: req.params.id, UserId: req.user.id } })
    res.json(basket)
  }
}

export function addBasketItem () {
  return async (req: Request, res: Response) => {
    const item = await BasketItemModel.create({ BasketId: req.body.BasketId, ProductId: req.body.ProductId, quantity: req.body.quantity })
    res.status(201).json(item)
  }
}
