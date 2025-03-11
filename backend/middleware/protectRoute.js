import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
const protectRoute = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    if (!token) {
      return res.status(401).json({ error: "Unauthorized - No token found" });
    }
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    if (!decodedToken) {
      return res.status(401).json({ error: "Unauthorized - Invalid token" });
    }
    const user = await User.findById(decodedToken.userId).select("-password");
    if (!user) {
      return res.status(401).json({ error: "Unauthorized - User not found" });
    }
    req.user = user;
    next();
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Server error" });
  }
};
export default protectRoute;
