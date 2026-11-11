// Mirrors Juice Shop routes/updateProductReviews.ts (challenges: NoSQL Manipulation, Forged Review)
import { type Request, type Response, type NextFunction } from 'express'
import * as db from '../../data/mongodb'

module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    db.reviewsCollection.update(
      { _id: req.body.id },
      { $set: { message: req.body.message } },
      { multi: true }
    ).then((result: any) => res.json(result), (err: unknown) => res.status(500).json(err))
  }
}
