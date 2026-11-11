// SAFE: queries built only from constants/enums, and ORM builder calls. No findings.
import * as models from '../../models/index'
import { UserModel } from '../../models/user'

const TABLE = 'Products'
enum Status { ACTIVE = 'active', DELETED = 'deleted' }

export function listActive () {
  return models.sequelize.query('SELECT * FROM ' + TABLE + " WHERE status = '" + Status.ACTIVE + "'")
}

export function listByEnv () {
  return models.sequelize.query(`SELECT * FROM ${process.env.PRODUCTS_TABLE} ORDER BY name`)
}

export function orm (req: any) {
  return UserModel.findAll({ where: { email: req.body.email } })
}

export function builder (knex: any, req: any) {
  return knex('users').where('email', req.body.email).first()
}
