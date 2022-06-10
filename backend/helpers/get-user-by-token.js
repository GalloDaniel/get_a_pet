const jwt = require('jsonwebtoken')

const User = require('../models/User')

// get user by jwt token
const getUserByToken = async (token) => {
  if (!token) {
    return res.status(401).json({ message: 'Acesso Negado!' })
  }

  const decoded = jwt.verify(token, 'nossosecret')

  const user = await User.findOne({ _id: decoded.id })

  return user
}

module.exports = getUserByToken