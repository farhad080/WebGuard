import { expressjwt as expressJwt } from 'express-jwt'

export const authenticatedUsers = new Map<string, { data: { id: number } }>()

export const isAuthorized = () => expressJwt({ secret: process.env.JWT_PUBLIC_KEY as string, algorithms: ['RS256'] })

export const isAdmin = () => (req: any, res: any, next: any) => (req.auth?.role === 'admin' ? next() : res.status(403).end())
