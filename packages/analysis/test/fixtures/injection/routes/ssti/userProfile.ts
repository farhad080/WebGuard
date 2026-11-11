// Mirrors Juice Shop routes/userProfile.ts (challenge: SSTi)
import { type Request, type Response, type NextFunction } from 'express'
import fs from 'fs/promises'
import pug from 'pug'
import { UserModel } from '../../models/user'

module.exports = function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const buf = await fs.readFile('views/userProfile.pug')
    const user = await UserModel.findByPk(req.cookies.userId)
    let username = user?.username
    if (username?.match(/#{(.*)}/) !== null) {
      const code = username?.substring(2, username.length - 1)
      username = eval(code)
    }
    let template = buf.toString()
    template = template.replace(/_username_/g, username)
    const fn = pug.compile(template)
    res.send(fn(user))
  }
}
