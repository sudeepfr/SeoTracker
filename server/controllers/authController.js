import User from "../models/User.js";
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

//Register
export const register = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "Please fill all the fields",
            })
        }
        const userExist = await User.findOne({ email });
        if (userExist) {
            return res.status(400).json({
                success: false,
                message: "User already exist"
            })
        }
        const hashedPassword = await bcrypt.hash(password, await bcrypt.genSalt(10));

        const user = await User.create({
            name,
            password: hashedPassword,
            email

        })
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });
        return res.status(201).json({
            success: true,
            token,
            user
        })

    } catch (error) {
        console.error("Register error", error.message);
        res.status(500).json({
            success: false,
            message: "Server error"
        })
    }
}


// login
export const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required !"
            })
        }
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Invalid credentals "
            })
        }
        const isMatch = await bcrypt.compare(password, user.password)
        if (!isMatch) {
            return res.status(400).json({
                success: false,
                messages: "Invalid credentals"
            })
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "30d" })
        return res.status(201).json({
            success: true,
            token,
            user,
        })
    } catch (error) {
        console.error("Register error", error.message);
        res.status(500).json({
            success: false,
            message: "Server error"
        })
    }

}

//get current user
export const getUser = async (req, res) => {
    try {
        const user = await User.findById(req.userId).select("-password")
        if(!user){
             return res.status(400).json({
                success:false,
                message:"User not found"
             })
        }
        res.status(201).json({
             success:true,
             user
        })
    } catch (error) {
        console.error("Register error", error.message);
        res.status(500).json({
            success: false,
            message: "Server error"
        })
    }
}
