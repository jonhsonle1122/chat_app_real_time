import dotenv from "dotenv";
import mongoose from "mongoose";
dotenv.config();
const connectToMongoDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`Database connected ${conn.connection.host}`);
  } catch (error) {
    console.log(error);
  }
};
export default connectToMongoDB;
