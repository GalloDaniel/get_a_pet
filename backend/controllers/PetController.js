const Pet = require('../models/Pet')

// helpers
const getToken = require('../helpers/get-token')
const getUserByToken = require('../helpers/get-user-by-token')
const ObjectId = require('mongoose').Types.ObjectId

module.exports = class PetController {
  static async create(req, res) {
    const { name, age, weight, color } = req.body
    const images = req.files
    const available = true

    // images uploads

    // validations
    if (!name) return res.status(422).json({ message: 'O nome é obrigatório' })
    if (!age) return res.status(422).json({ message: 'A idade é obrigatória' })
    if (!weight) return res.status(422).json({ message: 'O peso é obrigatório' })
    if (!color) return res.status(422).json({ message: 'A cor é obrigatória' })
    if (images.length === 0) return res.status(422).json({ message: 'A imagem é obrigatória' })

    // get pet owner
    const token = getToken(req)
    const user = await getUserByToken(token)

    // create a pet
    const pet = new Pet({
      name,
      age,
      weight,
      color,
      available,
      images: [],
      user: {
        _id: user.id,
        name: user.name,
        image: user.image,
        phone: user.phone
      }
    })

    images.map((image) => {
      pet.images.push(image.filename)
    })

    try {
      const newPet = await pet.save()
      res.status(201).json({ message: 'Pet cadastrado com sucesso!', newPet })
    } catch (err) {
      res.status(500).json({ message: err })
    }
  }

  static async getAll(req, res) {
    const pets = await Pet.find().sort('-createdAt')
    res.status(200).json({ pets })
  }

  static async getAllUserPets(req, res) {
    // get user from token
    const token = getToken(req)
    const user = await getUserByToken(token)
    const userID = user._id.toString()

    const pets = await Pet.find({ 'user._id': userID }).sort('-createdAt')

    res.status(200).json({ pets })
  }

  static async getAllUserAdoptions(req, res) {
    // get user from token
    const token = getToken(req)
    const user = await getUserByToken(token)

    const pets = await Pet.find({ "adopter._id": user._id }).sort('-createdAt')

    res.status(200).json({ pets })
  }

  static async getPetById(req, res) {
    const id = req.params.id

    // check if id is valid
    if (!ObjectId.isValid(id)) return res.status(422).json({ message: 'ID inválido' })

    // check if pet exists
    const pet = await Pet.findOne({ _id: id })

    if (!pet) return res.status(404).json({ message: 'Pet não encontrado' })

    res.status(200).json({ pet })
  }

  static async removePetById(req, res) {
    const id = req.params.id

    // check if id is valid
    if (!ObjectId.isValid(id)) return res.status(422).json({ message: 'ID inválido' })

    // check if pet exists
    const pet = await Pet.findOne({ _id: id })

    if (!pet) return res.status(404).json({ message: 'Pet não encontrado' })

    // check if logged in user registered the pet
    const token = getToken(req)
    const user = await getUserByToken(token)

    if (pet.user._id.toString() !== user._id.toString()) {
      return res.status(422).json({ message: 'Houve um problema em processar a sua solicitação, tente novamente mais tarde!' })
    }

    await Pet.findByIdAndRemove(id)

    res.status(200).json({ message: 'Pet removido com sucesso' })
  }

  static async updatePet(req, res) {
    const id = req.params.id
    const { name, age, weight, color, available } = req.body
    const images = req.files
    const updatedData = {}

    // check if pet exists
    const pet = await Pet.findOne({ _id: id })

    if (!pet) return res.status(404).json({ message: 'Pet não encontrado' })

    // check if logged in user registered the pet
    const token = getToken(req)
    const user = await getUserByToken(token)

    if (pet.user._id.toString() !== user._id.toString()) {
      return res.status(422).json({ message: 'Houve um problema em processar a sua solicitação, tente novamente mais tarde!' })
    }

    // validations
    if (!name) {
      return res.status(422).json({ message: 'O nome é obrigatório' })
    } else {
      updatedData.name = name
    }

    if (!age) {
      return res.status(422).json({ message: 'A idade é obrigatória' })
    } else {
      updatedData.age = age
    }

    if (!weight) {
      return res.status(422).json({ message: 'O peso é obrigatório' })
    } else {
      updatedData.weight = weight
    }

    if (!color) {
      return res.status(422).json({ message: 'A cor é obrigatória' })
    } else {
      updatedData.color = color
    }

    if (images.length === 0) {
      return res.status(422).json({ message: 'A imagem é obrigatória' })
    } else {
      updatedData.images = []
      images.map(image => updatedData.images.push(image.filename))
    }

    await Pet.findByIdAndUpdate(id, updatedData)

    res.status(200).json({ message: 'Pet atualizado com sucesso' })
  }

  static async schedule(req, res) {
    const id = req.params.id

    // check if pet exists
    const pet = await Pet.findOne({ _id: id })

    if (!pet) return res.status(404).json({ message: 'Pet não encontrado' })

    // check if logged in user registered the pet
    const token = getToken(req)
    const user = await getUserByToken(token)

    if (user._id.equals(pet.user._id)) {
      return res.status(422).json({ message: 'Você não pode agendar uma visita com o seu próprio Pet' })
    }

    // check if user has already scheduled a visit
    if (pet.adopter) {
      if (user._id.equals(pet.adopter._id)) {
        return res.status(422).json({ message: 'Você já agendou uma visita para este Pet!' })
      }
    }

    // add user to pet
    pet.adopter = {
      _id: user._id,
      name: user.name,
      image: user.image
    }

    await Pet.findByIdAndUpdate(id, pet)

    res.status(200).json({ message: `A visita foi agendada com sucesso, entre em contato com ${pet.user.name} pelo telefone ${pet.user.phone}` })
  }

  static async concludeAdoption(req, res) {
    const id = req.params.id

    // check if pet exists
    const pet = await Pet.findOne({ _id: id })

    if (!pet) return res.status(404).json({ message: 'Pet não encontrado' })

    // check if logged in user registered the pet
    const token = getToken(req)
    const user = await getUserByToken(token)

    if (pet.user._id.toString() !== user._id.toString()) {
      return res.status(422).json({ message: 'Houve um problema em processar a sua solicitação, tente novamente mais tarde!' })
    }

    pet.available = false

    await Pet.findByIdAndUpdate(id, pet)

    res.status(200).json({ message: 'Parabéns, o ciclo de adoção foi finalizado com sucesso!' })
  }
}