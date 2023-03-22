require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

// Config JSON response
app.use(express.json())

// Models
const User = require('./models/User')

// Open Route - Public Route
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Bem vindo a nossa API !' })
}) 

// Auth Route - Private Route
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id

// check if user exists
const user = await User.findById(id, '-password')

if (!user) {
    return res.status(404).json({ msg: 'Usuário não encontrado' })
}

res.status(200).json({ user })
})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(!token) {
        return res.status(401).json({ msg: 'Não autorizado' })
    }

    try {

        const secret = process.env.SECRET

        jwt.verify(token, secret) // verify token 

    } catch(error) {
        res.status(4000).json({msg: "Token inválido !"})
    }
}

// Register User
app.post('/auth/register', async(req, res) => {
    
    const { name, email, password, confirmpassword } = req.body

    // validations
    if(!name) {
        return res.status(422).json({ msg: 'Por favor, informe seu nome.' })
    }
    if(!email) {
        return res.status(422).json({ msg: 'Por favor, informe seu email.' })
    }
    if(!password) {
        return res.status(422).json({ msg: 'Por favor, informe sua senha.' })
    }

    if (password !== confirmpassword) {
        return res.status(422).json({ msg: 'As senhas não conferem.' })
    }

    // check if user exists
    const userExists = await User.findOne({ email: email })

    if(userExists) {
        return res.status(422).json({ msg: 'Por favor, utilize outro email !' })
    }

    // create password
    const salt = await bcrypt.genSalt(12) // 12 is the number of rounds
    const passwordHash = await bcrypt.hash(password, salt)

    // create user
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {
        await user.save()

        res.status(201).json({ msg: 'Usuario criado com sucesso !'})
    } catch(error) {
        console.log(error)

        res.status(500).json({
            msg: 'Aconteceu um erro no servidor, tente novamente mais tarde !'
        })
    }
})

// Login User
app.post('/auth/login', async(req, res) => {
    const { email, password } = req.body

    // validations
    if(!email) {
        return res.status(422).json({ msg: 'Por favor, informe seu email.' })
    }

    if(!password) {
        return res.status(422).json({ msg: 'Por favor, informe sua senha.' })
    }

    // check if user exists
    const user = await User.findOne({ email: email})

    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado' })
    }

    // check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword) {
        return res.status(422).json({ msg: 'Senha inválida' }) 
    }

    try {

        const secret = process.env.SECRET

        const token = jwt.sign(
            { 
                id: user._id 
            }, 
            secret, 
        )

        res.status(200).json({ msg: 'Autenticação realizada com sucesso !', token: token })

    } catch (err) {
        console.log(error)

        res.status(500).json({
            msg: 'Aconteceu um erro no servidor, tente novamente mais tarde !'
        })
    }

})


// credenciais
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose
.connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.bzsc5us.mongodb.net/?retryWrites=true&w=majority`
    )
.then(() => {
    app.listen(3000)
    console.log('Conectado ao banco de dados')
})
.catch((err) => console.log(err))



