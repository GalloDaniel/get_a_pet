const User = require('../models/User')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

// Helpers
const createUserToken = require('../helpers/create-user-token')
const getToken = require('../helpers/get-token')
const { json } = require('express/lib/response')
const getUserByToken = require('../helpers/get-user-by-token')

module.exports = class UserController {
  static async register(req, res) {
    const { name, email, phone, password, confirmpassword } = req.body

    // validations
    if (!name) {
      return res.status(422).json({ message: 'O nome é obrigatório' })
    }

    if (!email) {
      return res.status(422).json({ message: 'O e-mail é obrigatório' })
    }

    if (!phone) {
      return res.status(422).json({ message: 'O telefone é obrigatório' })
    }

    if (!password) {
      return res.status(422).json({ message: 'A senha é obrigatória' })
    }

    if (!confirmpassword) {
      return res.status(422).json({ message: 'A confirmação da senha é obrigatória' })
    }

    if (password !== confirmpassword) {
      return res.status(422).json({ message: 'A senha e a confirmação de senha precisam ser iguais!' })
    }

    // check if user exists
    const userExits = await User.findOne({ email })
    if (userExits) {
      return res.status(422).json({ message: 'Por favor, utilize outro e-mail' })
    }

    // create a password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // create a user
    const user = new User({
      name,
      email,
      phone,
      password: passwordHash
    })

    try {
      const newUser = await user.save()

      await createUserToken(newUser, req, res)
    } catch (err) {
      res.status(500).json({ message: err })
    }
  }

  static async login(req, res) {
    const { email, password } = req.body

    if (!email) {
      return res.status(422).json({ message: 'O e-mail é obrigatório' })
    }
    if (!password) {
      return res.status(422).json({ message: 'A senha é obrigatória' })
    }

    const user = await User.findOne({ email })

    if (!user) {
      return res.status(422).json({ message: 'Não há usuário cadastrado com este e-mail!' })
    }

    // check if password match with db password
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword) {
      return res.status(422).json({ message: 'Senha invalida!' })
    }

    await createUserToken(user, req, res)

  }

  static async checkUser(req, res) {
    let currentUser

    if (req.headers.authorization) {
      const token = getToken(req)
      const decoded = jwt.verify(token, 'nossosecret')

      currentUser = await User.findById(decoded.id)

      currentUser.password = undefined
    } else {
      currentUser = null
    }

    res.status(200).send(currentUser)

  }

  static async getUserById(req, res) {
    const id = req.params.id

    const user = await User.findById(id).select('-password')

    if (!user) {
      return res.status(422).json({ message: 'Usuário não encontrado!' })
    }

    res.status(200).json({ user })
  }

  static async editUser(req, res) {
    const id = req.params.id

    // check if user exists
    const token = getToken(req)
    const user = await getUserByToken(token)

    const { name, email, phone, password, confirmpassword } = req.body

    let image = ''

    if (req.file) {
      user.image = req.file.filename
    }

    // validations
    if (!name) {
      return res.status(422).json({ message: 'O nome é obrigatório' })
    }

    user.name = name

    if (!email) {
      return res.status(422).json({ message: 'O e-mail é obrigatório' })
    }

    // check if email has already taken
    const userExits = await User.findOne({ email })

    if (user.email !== email && userExits) {
      return res.status(422).json({ message: 'Por favor, utilize outro e-mail!' })
    }

    user.email = email

    if (!phone) {
      return res.status(422).json({ message: 'O telefone é obrigatório' })
    }

    user.phone = phone

    if (password !== confirmpassword) {
      return res.status(422).json({ message: 'A senha e a confirmação de senha precisam ser iguais!' })
    } else if (password === confirmpassword && password != null) {
      // creating password
      const salt = await bcrypt.genSalt(12)
      const passwordHash = await bcrypt.hash(password, salt)

      user.password = passwordHash
    }

    try {
      // returns user updated data
      await User.findByIdAndUpdate(
        { _id: user._id },
        { $set: user },
        { new: true }
      )

      res.status(200).json({ message: 'Usuário atualizado com sucesso!' })
    } catch (err) {
      return res.status(500).json({ message: err })
    }
  }
}