import { type Request, type Response } from 'express'
import { FeedbackModel } from '../models/feedback'

export function deleteFeedback () {
  return async (req: Request, res: Response) => {
    await FeedbackModel.destroy({ where: { id: req.params.id } })
    res.status(204).end()
  }
}

// #23 Forged Feedback: the client can post feedback in another user's name via UserId
export function createFeedback () {
  return async (req: Request, res: Response) => {
    const feedback = await FeedbackModel.create(req.body)
    res.status(201).json(feedback)
  }
}
