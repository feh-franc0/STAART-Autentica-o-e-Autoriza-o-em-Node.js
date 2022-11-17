const jwtlib = require('jsonwebtoken')
const { AuthenticationError } = require('../errors')
const { jwt } = require('../config')

const jwtAuth = async (req, res, next) => {
  try {
    const header = req.get('Authorization')
    if (!header) throw new AuthenticationError('No token provided')
    // Bearer <jwt> -> [Bearer, <jwt>]
    const token = header.split(' ')[1]
    const decoded = jwtlib.verify(token, jwt.secret, {
      audience: jwt.audience,
      issuer: jwt.issuer,
    })
    req.user = decoded
    next()
  } catch (error) {
    if (error instanceof jwtlib.JsonWebTokenError) return next(new AuthenticationError('Invalid Token'))
    next(error)
  }
}

module.exports = {
  jwtAuth
}
