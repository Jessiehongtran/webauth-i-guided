const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs')

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let {username, password} = req.body;
  const hash = bcrypt.hashSync(password,14) // it's 2^14 rounds

  Users.add({username, password: hash})
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

//write a middleware that will check for the username and password  
//and let the request continue to /api/users if credentials are good  
//return a 401 if the credentials are invalid

//Use the middleware to restrict access to the GET /api/users endpoint
function validateUser(req,res,next,username,password){
  if (username !==req.body.username || password !== req.body.password){
    res.status(401).json({message: "invalid username or password"})
  } else if (req.body.name){
    next()
  }
}

server.get('/api/users', validateUser, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.get('/hash', (req,res)=> {
  const name = req.query.name;
  //hash the name
  const hash = bcrypt.hashSync(name, 10);
  res.send(`the hash for ${name} is ${hash}`);
  
})




const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));


