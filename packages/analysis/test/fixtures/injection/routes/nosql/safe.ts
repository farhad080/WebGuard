// SAFE: coerced scalar selectors, Array#find, route-param equality. No findings.
import { type Request, type Response } from 'express'
import * as db from '../../data/mongodb'

export function update (req: Request, res: Response) {
  return db.reviewsCollection.update({ _id: String(req.body.id) }, { $set: { message: String(req.body.message) } })
}

export function byNumber (req: Request, res: Response) {
  return db.reviewsCollection.findOne({ product: Number(req.body.product) })
}

export function inMemory (req: Request, items: Array<{ id: string }>) {
  return items.find((i) => i.id === req.body.id)
}

export function byRouteParam (req: Request) {
  return db.ordersCollection.findOne({ orderId: req.params.id })
}
