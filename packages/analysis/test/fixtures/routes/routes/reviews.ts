// SAFE: bearer-token API (express-jwt via security.isAuthorized()); ProductId is not owned data.
import { type Response } from 'express'
import { ReviewModel } from '../models/review'

export function postReview () {
  return async (req: any, res: Response) => {
    const review = await ReviewModel.create({ message: req.body.message, author: req.auth.email, ProductId: req.params.id })
    res.status(201).json(review)
  }
}
