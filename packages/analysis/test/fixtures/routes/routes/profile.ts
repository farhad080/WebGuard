// Mirrors Juice Shop routes/updateUserProfile.ts (#25 CSRF): authenticated by the `token` cookie.
import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

export function updateUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) return next(new Error('Blocked illegal activity'))
    const user = await UserModel.findByPk(loggedInUser.data.id)
    await user.update({ username: req.body.username })
    res.redirect('/profile')
  }
}
