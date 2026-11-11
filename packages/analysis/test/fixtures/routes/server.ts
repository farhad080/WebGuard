// Juice Shop-style Express server wiring (mirrors server.ts route registration).
import express from 'express'
import session from 'express-session'
import * as security from './lib/insecurity'
import { validate, userSchema } from './lib/validation'
import { deleteFeedback, createFeedback } from './routes/feedback'
import { retrieveBasket, retrieveBasketByPk, retrieveOwnBasket, addBasketItem } from './routes/basket'
import { registerUser, registerUserSafe, createValidated, exportUser, deleteUser, retrieveAppConfiguration } from './routes/users'
import { updateUserProfile } from './routes/profile'
import { postReview } from './routes/reviews'
import { saveSettings, requireLogin, csrfProtection } from './routes/settings'

const app = express()
app.use(express.json())
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }))

// #22: anyone can delete feedback (no authz on the API)
app.delete('/api/Feedbacks/:id', deleteFeedback())
// SAFE: admin-only delete
app.delete('/api/Users/:id', security.isAuthorized(), security.isAdmin(), deleteUser())

// #21: authenticated, but any basket id can be viewed
app.get('/rest/basket/:id', security.isAuthorized(), retrieveBasket())
app.get('/rest/basket-pk/:id', security.isAuthorized(), retrieveBasketByPk())
// SAFE: ownership predicate
app.get('/rest/basket-own/:id', security.isAuthorized(), retrieveOwnBasket())
// #24: add an item to someone else's basket
app.post('/api/BasketItems', security.isAuthorized(), addBasketItem())

// #20: admin configuration with no server-side protection
app.get('/rest/admin/application-configuration', retrieveAppConfiguration())

// #23 / mass assignment
app.post('/api/Users', registerUser())
app.post('/api/Feedbacks', security.isAuthorized(), createFeedback())
// SAFE: allowlisted / validated bodies
app.post('/api/Users-safe', registerUserSafe())
app.post('/api/Users-validated', validate(userSchema), createValidated())

// #13: client-chosen attributes
app.get('/api/Users/:id/export', security.isAuthorized(), exportUser())

// #25: cookie-authenticated profile update, no CSRF protection
app.post('/profile', updateUserProfile())
// SAFE (CSRF): bearer-token API
app.post('/api/Products/:id/reviews', security.isAuthorized(), postReview())
// SAFE (CSRF): session route with a CSRF token check
app.post('/settings', requireLogin, csrfProtection, saveSettings)

app.listen(3000)
