// Stored XSS (challenge #30): the email format is only validated in the browser; the API
// stores whatever it receives, and the admin page renders it as HTML.
import { type Request, type Response } from 'express'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

export async function register (req: Request, res: Response) {
  const user = await UserModel.create({ email: req.body.email, password: security.hash(req.body.password) })
  res.status(201).json({ id: user.id })
}
