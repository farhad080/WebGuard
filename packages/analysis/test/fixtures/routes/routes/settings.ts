// SAFE: session-authenticated, CSRF-token protected, owner-scoped update.
import { doubleCsrf } from 'csrf-csrf'
import { SettingsModel } from '../models/settings'

export const { doubleCsrfProtection: csrfProtection } = doubleCsrf({ getSecret: () => process.env.CSRF_SECRET as string })

export function requireLogin (req: any, res: any, next: any) {
  return req.session?.userId ? next() : res.status(401).end()
}

export async function saveSettings (req: any, res: any) {
  await SettingsModel.update({ theme: req.body.theme }, { where: { UserId: req.session.userId } })
  res.json({ ok: true })
}
