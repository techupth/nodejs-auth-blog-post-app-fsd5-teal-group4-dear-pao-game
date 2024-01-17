import { Router } from "express"
import bcrypt from "bcrypt";
import { db } from "../utils/db.js";
import jwt from "jsonwebtoken"

const authRouter = Router();


// 🐨 Todo: Exercise #1
// ให้สร้าง API เพื่อเอาไว้ Register ตัว User แล้วเก็บข้อมูลไว้ใน Database ตามตารางที่ออกแบบไว้
authRouter.post("/register", async (req, res) => {
    //1.รับ body จาก user
	const user = {
		username: req.body.username,
		password: req.body.password,
		firstName: req.body.firstName,
		lastName: req.body.lastName
	}

    //2.bcrypt package // npm i bcrypt // npm install bcrypt
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password, salt) // เป็นการ Encrypt user.password ด้วย Function bcrypt.hash

	const collection = db.collection("users");
	await collection.insertOne(user)

	return res.json({
		message: "User has been created successfully"
	})
})

// 🐨 Todo: Exercise #3
// ให้สร้าง API เพื่อเอาไว้ Login ตัว User ตามตารางที่ออกแบบไว้
authRouter.post("/login", async (req, res) => {
	const user = await db.collection("users").findOne({
		  username: req.body.username
	  })
  
	if (!user) {
	  return res.status(404).json({
			  "message": "user not found"
		  })
	}
  
	  const isValidPassword = await bcrypt.compare(req.body.password, user.password);
  
	if (!isValidPassword) {
		  return res.status(401).json({
			  "message": "password not valid"
		  })
	}
	  
	// ส่วนที่ใช้สร้าง Token
	  const token = jwt.sign(
	  //เป็นส่วนที่ระบุข้อมูลที่จะแนบเข้าไปใน Token
	  {
			  id: user.id,
			  firstName: user.firstName,
			  lastName: user.lastName
		  },
	  process.env.SECRET_KEY, // เป็นส่วนที่ใช้ Object process.env ในการ Access ตัว Environment Variable
	  {
		expiresIn: '900000', //เป็นส่วนที่ระบุว่าให้ Token ของเราหมดอายุใน 900000 ms ซึ่งมีค่าเท่ากับ 15 นาที (หรือ 900 วินาทีนั่นเอง)
	  }
	);
  
	return res.json({ 
		  message: "login succesfully",
		  token 
	  })
  });

export default authRouter;
