const express=require('express');
const colors=require('colors');
const morgan=require('morgan');
const dotenv=require('dotenv');
const connectDB = require('./config/db');

//dotenv config
dotenv.config();

//mongoDB connection
connectDB();

//rest object
const app=express();


//middlewares
app.use(express.json());
app.use(morgan('dev'));


//routes
app.use('/api/v1/user',require('./routes/userRoutes'))


//port
const port=process.env.PORT||8080

//listen port
app.listen(port,()=>{
    console.log(colors.green(`server running on port ${process.env.NODE_MODE} mode on port ${port}`).bgCyan.white);
})