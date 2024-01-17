import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { jwtDecode } from "jwt-decode";

const AuthContext = React.createContext();

function AuthProvider(props) {
  
  const [state, setState] = useState({
    loading: null,
    error: null,
    user: null,
  });

    // 🐨 Todo: Exercise #4
    //  ให้เขียน Logic ของ Function `login` ตรงนี้
    //  Function `login` ทำหน้าที่สร้าง Request ไปที่ API POST /login
    //  ที่สร้างไว้ด้านบนพร้อมกับ Body ที่กำหนดไว้ในตารางที่ออกแบบไว้
    const login = async (data) => {
      const result = await axios.post("http://localhost:4000/auth/login", data)
    
      //เป็นการนำ Token ที่ได้มาจาก Response ของ Server ไปเก็บไว้ใน Local Storage
      const token = result.data.token // ถ้าการ Login เสร็จสมบูรณ์ ฝั่ง Server ก็จะส่ง Token กลับมาใน Response และเราต้องเอา Token นี้ไปเก็บใน Local Storage 
      //localStorage.set("token", token) // ไม่ได้
      localStorage.setItem("token", token)
      const userDataFromToken = jwtDecode(token);
      setState({ ...state, user: userDataFromToken })
      navigate("/");
    };


    // 🐨 Todo: Exercise #2
    //  ให้เขียน Logic ของ Function `register` ตรงนี้
    //  Function register ทำหน้าที่สร้าง Request ไปที่ API POST /register
    //  ที่สร้างไว้ด้านบนพร้อมกับ Body ที่กำหนดไว้ในตารางที่ออกแบบไว้
    const register = async (data) => {
      await axios.post("http://localhost:4000/auth/register", data);
      navigate("/login");
  };


  const logout = () => {
    // 🐨 Todo: Exercise #7
    //  ให้เขียน Logic ของ Function `logout` ตรงนี้
    //  Function logout ทำหน้าที่ในการลบ JWT Token ออกจาก Local Storage
  };

  const isAuthenticated = Boolean(localStorage.getItem("token"));

  return (
    <AuthContext.Provider
      value={{ state, login, logout, register, isAuthenticated }}
    >
      {props.children}
    </AuthContext.Provider>
  );
}

// this is a hook that consume AuthContext
const useAuth = () => React.useContext(AuthContext);

export { AuthProvider, useAuth };
