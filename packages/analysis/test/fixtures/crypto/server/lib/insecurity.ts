// Mirrors Juice Shop lib/insecurity.ts (#39 weak password hashing, #40 z85 "encrypted" coupons)
import crypto from 'crypto'
import * as z85 from 'z85'

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon: string) => {
  const decoded = z85.decode(coupon)
  const parts = decoded.toString().split('-')
  return parts.length === 2 ? parseInt(parts[1], 10) : undefined
}

function toMMMYY (date: Date) {
  return date.toLocaleString('en-US', { month: 'short' }).toUpperCase() + String(date.getFullYear()).slice(2)
}
