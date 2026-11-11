import { z } from 'zod'

export const userSchema = z.object({ email: z.string().email(), password: z.string().min(8) }).strict()

export function validate (schema: z.ZodTypeAny) {
  return (req: any, res: any, next: any) => {
    const result = schema.safeParse(req.body)
    if (!result.success) return res.status(400).json(result.error)
    req.body = result.data
    next()
  }
}
