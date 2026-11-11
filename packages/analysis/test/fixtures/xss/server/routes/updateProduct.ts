// Stored XSS (challenge #29 API-only XSS): the description is written straight from the
// request body and later rendered with bypassSecurityTrustHtml on the search/product page.
import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'

module.exports = function updateProduct () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const product = await ProductModel.findByPk(req.params.id)
    await product.update({ description: req.body.description, price: Number(req.body.price) })
    res.json(product)
  }
}
