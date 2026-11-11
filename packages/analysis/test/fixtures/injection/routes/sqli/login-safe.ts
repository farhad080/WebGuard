// SAFE: parameterized versions (Juice Shop's own fixes). Must produce no findings.
import { type Request, type Response } from 'express'
import * as models from '../../models/index'
import * as security from '../../lib/insecurity'
import { UserModel } from '../../models/user'

export function login (req: Request, res: Response) {
  return models.sequelize.query('SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL',
    { bind: [req.body.email, security.hash(req.body.password)], model: UserModel, plain: true })
}

export function search (req: Request, res: Response) {
  const criteria = req.query.q
  return models.sequelize.query('SELECT * FROM Products WHERE name LIKE :criteria',
    { replacements: { criteria: `%${criteria}%` } })
}

export function byId (req: Request, res: Response) {
  return models.sequelize.query('SELECT * FROM Products WHERE id = ' + Number(req.params.id))
}

export function escaped (req: Request, res: Response) {
  return models.sequelize.query('SELECT * FROM Users WHERE email = ' + models.sequelize.escape(req.body.email))
}
