const express=require('express');
const mariadb=require('mariadb');
const cors=require('cors');
const port=4000;
require('dotenv').config();
const transporter=require('./transpoter');
const paths=require('./assets/transglobe/path');
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');
const fs=require('fs');
const cookieParser=require('cookie-parser')


const app=express();

app.use(cors({
    origin:process.env.ORIGIN_CORS,
    credentials:true
}));

app.use(express.json());

app.use(cookieParser());

const pool=mariadb.createPool({
    user:'learn',
    host:'localhost',
    password:process.env.PASSWORD_DB,
    database:'transglobe',
    connectionLimit:5
});

const PUBLIC_KEY=fs.readFileSync('./public.pem','utf8');
const PRIVATE_KEY=fs.readFileSync('./private.pem','utf8');

const verifyUser= async (req,res,next)=>{
    const {email,password}=req.body;
    const connection=await pool.getConnection();
    try{
        const user=await connection.query("SELECT email FROM utilisateur WHERE email=?",[email]);
        if(user.length!==0){
            return res.status(400).json({success:false,message:"Cet utilisateur existe déjà !"});
        }
        next();
    }catch(err){
        console.log(err);
    }finally{
        if(connection) connection.release();
    }
}
const verifyUserExist= async (req,res,next)=>{
    const {email,password}=req.body;
    const connection=await pool.getConnection();
    try{
        const user=await connection.query("SELECT email FROM utilisateur WHERE email=?",[email]);
        if(user.length==0){
            return res.status(400).json({success:false,message:"Cet utilisateur n'as pas de compte !"});
        }
        next();
    }catch(err){
        console.log(err);
    }finally{
        if(connection) connection.release();
    }
}

const verifyRefreshToken=async (req,res,next)=>{
    const token=req.cookies.RefreshToken;
    if(!token) return res.json({success:false,message:"Pas de RefreshToken trouvé !"});
    jwt.verify(token,PUBLIC_KEY,{algorithm:'ES256'},(err,user)=>{
        if(err) return res.json({success:false,message:'Tocken invalide !'});
        req.user={email:user.email,id:user.id}
        next();
    });
}

app.post('/delOtp',async(req,res)=>{
    const connection=await pool.getConnection();
    const {email}=req.body;
    try{
        await connection.query("DELETE FROM otp WHERE email=?",[email]);
        res.json({success:true,message:"OTP supprimé avec succès !"});
    }catch(err){
        console.log(err);
        res.json({success:false,message:"Erreur du serveur !"});
    }finally{
        if (connection) connection.release();
    }
})

app.post('/signUp',verifyUser,async (req,res)=>{
    const connection=await pool.getConnection();
    const {email,password}=req.body;
    const otp=Math.floor(100000+Math.random()*900000);
    try{
        await transporter.sendMail({
                from:process.env.EMAIL_USER,
                to:email,
                subject:'Votre code OTP!',
                html:`<h1>Bienvenue chez Transglobe !</h1><br/><p>Votre code OTP est: <b>${otp}</b></p><br/><img src="cid:Logo" alt="Logo Transglobe"/><br/>`,
                attachments:[{
                    filename:"transglobeLogoViolet.png",
                    path:paths.logo,
                    cid:"Logo"
                }]
        });
        await connection.query("DELETE FROM otp WHERE email=?",[email]);
        await connection.query("INSERT INTO otp(email,otp) VALUES(?,?)",[email,otp]);
        setTimeout(async ()=>{
            const conn = await pool.getConnection();
            try {
                await conn.query("DELETE FROM otp WHERE email=?", [email]);
                console.log(`OTP supprimé pour ${email}`);
            } catch (err) {
                console.error(`Erreur lors de la suppression OTP:`, err);
            } finally {
                conn.release();
            }
        },300000)
        res.status(200).json({ success: true, message: "Code OTP envoyé avec succès !" });
    }catch(err){
        console.log(err);
        res.status(500).json({success:false,message:"Erreur du serveur !"});
    }finally{
        if(connection) connection.release();
    }
})

app.post('/verifyOtp',async (req,res)=>{
    const connection=await pool.getConnection();
    const {email,password,otp}=req.body;
    try{
        const row=await connection.query("SELECT * FROM otp WHERE email=?",[email]);
        if(row.length===0){
            return res.status(400).json({success:false,message:"Demandez un nouveau code OTP !"});
        }else if(row[0].otp!=otp){
            return res.status(400).json({success:false,message:"Code OTP incorrect !"});
        }
        const passwordhasted=await bcrypt.hash(password,10);
        const verifyExist=await connection.query("SELECT email FROM utilisateur WHERE email=?",[email]);
        if(verifyExist.length==0){
            await connection.query("INSERT INTO utilisateur(email,password) VALUES(?,?)",[email,passwordhasted]);
            await connection.query("DELETE FROM otp WHERE email=?",[email]);
            return res.status(200).json({success:true,message:"Inscription réussie !"});
        }else{
            await connection.query("DELETE FROM otp WHERE email=?",[email]);
        return res.status(200).json({success:true,message:"Connexion réussie !"});
        }
    }catch(err){
        console.log(err);
        res.status(500).json({success:false,message:"Erreur du serveur !"});
    }finally{
        if(connection) connection.release();
    }
})

app.post('/creer-jwt',async (req,res)=>{
    const connection=await pool.getConnection();
    const {email}=req.body
    try{
        const rows=await connection.query("SELECT id from utilisateur where email=?",[email])
        const id=rows[0].id
        const AccessToken=jwt.sign({email,id},PRIVATE_KEY,{algorithm:'ES256',expiresIn:'2min'})
        const RefreshToken=jwt.sign({email,id},PRIVATE_KEY,{algorithm:'ES256',expiresIn:'7d'})
        res.cookie('AccessToken',AccessToken,{
            httpOnly:true,
            secure:false,
            sameSite:'strict',
            maxAge:2*60*1000,
        });
        res.cookie('RefreshToken',RefreshToken,{
            httpOnly:true,
            secure:false,
            sameSite:'strict',
            maxAge:7*24*60*60*1000,
        })
        res.status(201).json({success:true,message:'Votre JW à été créé et stocké dans les cooKies !'});
        console.log("Votre JW à été créé et stocké dans les cooKies !");
    }catch(err){
        console.log(err);
        res.status(500).json({success:false,message:"Erreur du serveur !"});
    }finally{
        if(connection) connection.release();
    }
})

app.post('/verify-refreshToken',verifyRefreshToken,async (req,res)=>{
    const connection=await pool.getConnection();
    const user=req.user;
    try{
        const AccessToken=jwt.sign(user,PRIVATE_KEY,{algorithm:'ES256',expiresIn:'2min'});
        res.cookie('AccessToken',AccessToken,{
            httpOnly:true,
            secure:false,
            sameSite:'strict',
            maxAge:2*60*1000,
        });
        res.status(201).json({success:true,message:'Votre Access token a été mis à jour et stocké dans les cooKies !'});
        console.log("Votre Access token a été stocké dans les cooKies !");
    }catch(err){
        console.log(err);
        res.status(500).json({success:false,message:"Erreur du serveur !"});
    }finally{
        if(connection) connection.release();
    }
})

app.post('/check-refreshToken',verifyRefreshToken,async(req,res)=>{
    res.json({success:true,message:'jwt existe!',user:req.user})
})

app.post("/login",verifyUserExist,async (req,res)=>{
    const {email,password}=req.body;
    const connection= await pool.getConnection();
    const otp=Math.floor(100000+Math.random()*900000);
    try{
        const infos=await connection.query("SELECT passWord FROM utilisateur where email=?",[email]);
        const motDePasse=infos[0].passWord
        const match=await bcrypt.compare(password,motDePasse);
        if(match){
            res.status(201).json({success1:true,message:"Utilisateur vérifié avec success !"})
            try{
                console.log("Envoie du mail OTP!")
                await transporter.sendMail({
                    from:process.env.EMAIL_USER,
                    to:email,
                    subject:"Votre code OTP de connection à Transglobe !",
                    html:`<h1>Ravis de vous revoir à Transglobe!</h1><br/><p>Votre code OTP de connexion est <b>${otp}</b></p><br/><img src="cid:logo" alt="Logo TransGlobe"><br/>`,
                    attachments:[{
                        filename:"transglobeLogoViolet.png",
                        paths:paths.logo,
                        cid:"logo"
                    }]
                })
                await connection.query("DELETE FROM otp WHERE email=?",[email]);
                await connection.query("INSERT INTO otp(email,otp) VALUES(?,?)",[email,otp]);
                setTimeout(async ()=>{
                    const conn = await pool.getConnection();
                    try {
                        await conn.query("DELETE FROM otp WHERE email=?", [email]);
                        console.log(`OTP supprimé pour ${email}`);
                    } catch (err) {
                        console.error(`Erreur lors de la suppression OTP:`, err);
                    } finally {
                        conn.release();
                    }
                },300000)
            }catch(err){
                console.log(err)
            }
            
        }else{
            res.status(200).json({success1:false,message:"Mot de passe incorrect !"});
        }
        
    }catch(err){
        res.status(500).json({success:false,message:"Une erreur s'est produite lors de la connection de l'utilisateur!"})
        console.log(`ERREUR:${err}`)
    }finally{
        if(connection) connection.release();
    }
})


app.listen(port,()=>{
    console.log('Server is running on port '+port);
})