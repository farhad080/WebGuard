// Mirrors Juice Shop routes/login.ts (challenges: Login Admin, Login Jim, Login Bender, ...)
import { type Request, type Response, type NextFunction } from 'express'
import * as models from '../../models/index'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'

module.exports = function login () {
  return (req: Request, res: Response, next: NextFunction) => {
    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
      .then((authenticatedUser: any) => res.json(authenticatedUser))
      .catch((error: Error) => next(error))
  }
}
