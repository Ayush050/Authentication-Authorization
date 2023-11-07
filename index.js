
const express=require('express'); 
const bodyParser=require('body-parser'); 
const cors=require('cors'); 
require('dotenv').config();
const User=require('./MODELS/userSchema');
const app=express();
app.use(bodyParser.json());
app.use(cors());
require('./db'); 
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');

function authenticatetoken(req, resp, next) {
     var token = req.headers.authorization;
     var id=req.body;
  
    if (!token) {
      return resp.status(401).json({
        message: "Unauthorized access"
      });
    }
    
   
    try {
    
      const user = jwt.verify(token, process.env.JWT_SECRET_KEY); // Verify the token with the secret key
    
      id = user.id; // Store the user object in the request for later use

      next();
    } 
    catch (err) {
        return resp.status(401).json({ // Change status code to 401 for invalid token
        message: "Invalid token"
      });
    }
  }

        app.post('/register', async (req,resp)=>{
            try{
                const {name,password,email,age,gender}=req.body;
                const existingUser= await User.findOne({email}); 
                if(existingUser){
                    return resp.status(400).json({
                        message:"Email already exists"
                    })
                } 

                const salt=await bcrypt.genSalt(10); // this is basically a random string which is used to hash the password
                const hashedPassword = await bcrypt.hash(password, salt); // here we are converting the password into hash so that anyone can not understand the password
                const newUser=new User({
                    name,
                    password:hashedPassword,
                    email,
                    age,
                    gender,
                }) 

                await newUser.save();  // it will save the data in the database

                resp.status(201).json({
                        message:"User registered successfully"
                })
        
            } 
            catch(err){
                resp.status(500).json({
                    message:"Internal server error"
                })
            }
        }) 


        app.post('/login',async (req,resp)=>{
            const {email,password}=req.body;
            const existingUser=await User.findOne({email});
                if(!existingUser){
                return resp.status(401).json({
                    message:"Invalid user credentials"
                })
        } 

        const isPasswordCorrect=await bcrypt.compare(password,existingUser.password); // here we are comparing the password which user has entered with the password which is stored in the database
            if(!isPasswordCorrect){
                return resp.status(401).json({
                    message:"Invalid user credentials"
                })
            } 
            
            const token=jwt.sign({id:existingUser._id},process.env.JWT_SECRET_KEY); // here we are creating a token which will be used to authenticate the user
                
            resp.status(200).json({
                token,
                message:"User logged in successfully"
            }) 
        }) 

        app.get('/getmyprofile', authenticatetoken, async (req, resp) => {
            const {id}=req.body; 
            const user=await User.findById(id); 
            user.password=undefined;
            resp.status(200).json({
              user
            })
        });  

 
          

        app.listen(5000,()=>{
            console.log("server is running on port 5000")
        })
