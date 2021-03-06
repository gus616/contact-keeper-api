const express = require('express');
const app = express();
const connectDB = require('./config/db');
const cors = require('cors');

//Allow CORS policy
app.use(cors());
//Connect to Database
connectDB();

//Init Middleware
app.use(express.json({extended: false}));


//app.get('/', (req, res)=> res.send('Hello World'));
app.get('/', (req, res)=> res.json({msg: 'Hello from the Contact Keeper API'}));

//Define Routes
app.use('/api/users', require('./routes/users'));
app.use('/api/auth', require('./routes/auth'));
app.use('/api/contacts', require('./routes/contacts'));


const PORT = process.env.PORT || 5000;
app.listen(PORT, ()=> console.log(`Server started in port: ${PORT}`));