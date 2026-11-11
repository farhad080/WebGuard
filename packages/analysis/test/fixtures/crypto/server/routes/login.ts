// Calls the MD5-based security.hash() with the submitted password (Juice Shop #39).
import { type Request, type Response } from 'express'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

export async function login (req: Request, res: Response) {
  const user = await UserModel.findOne({ where: { email: req.body.email, password: security.hash(req.body.password) } })
  res.json({ authenticated: Boolean(user) })
}
