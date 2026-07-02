import jwt from 'jsonwebtoken'

export const auth=async(req,res,next)=>{
     try {
        const authHeader=req.headers.authorization;
        if(!authHeader||!authHeader.startsWith("Bearer ")){
             return res.status(401).json({
                 success:false,
                 message:"Token not found"
             })
        }
        const token=authHeader.split(" ")[1];
        const decoded=await jwt.verify(token,process.env.JWT_SECRET)
        req.userId=decoded.id;
        next();
     } catch (error) {
         console.error("Auth middlewere error",error.message);
         return res.status(401).json({
            success:false,
            message:"Not authorized ,token failed"
         })
     }
} 

