// Mirrors Juice Shop routes/showProductReviews.ts (challenge: NoSQL DoS via $where)
import { type Request, type Response, type NextFunction } from 'express'
import * as db from '../../data/mongodb'

module.exports = function productReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const id = req.params.id
    db.reviewsCollection.find({ $where: 'this.product == ' + id }).then((reviews: any) => res.json(reviews))
  }
}
