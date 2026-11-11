import { type Request, type Response } from 'express'
import pick from 'lodash/pick'
import { UserModel } from '../models/user'

// Mass assignment: { "email": "...", "password": "...", "role": "admin" } creates an admin
export function registerUser () {
  return async (req: Request, res: Response) => {
    const user = await UserModel.create(req.body)
    res.status(201).json({ id: user.id })
  }
}

// SAFE: explicit allowlist
export function registerUserSafe () {
  return async (req: Request, res: Response) => {
    const user = await UserModel.create(pick(req.body, ['email', 'password']))
    res.status(201).json({ id: user.id })
  }
}

// SAFE: body validated by a strict schema in the route's middleware chain
export function createValidated () {
  return async (req: Request, res: Response) => {
    const user = await UserModel.create(req.body)
    res.status(201).json({ id: user.id })
  }
}

// #13: the client chooses which columns come back (password hash, totpSecret, ...)
export function exportUser () {
  return async (req: any, res: Response) => {
    const user = await UserModel.findByPk(req.auth.id, { attributes: req.query.fields.split(',') })
    res.json(user)
  }
}

// SAFE for IDOR: the route requires an admin
export function deleteUser () {
  return async (req: Request, res: Response) => {
    await UserModel.destroy({ where: { id: req.params.id } })
    res.status(204).end()
  }
}

export function retrieveAppConfiguration () {
  return (req: Request, res: Response) => {
    res.json({ config: { application: { name: 'Shop' }, server: { port: 3000 } } })
  }
}
