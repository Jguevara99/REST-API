import { createAccesToken } from "../libs/jwt";
import User from "../models/user.model";
import bcryp from "bcryptjs";
import jwt from "jsonwebtoken";
import { TOKEN_SECRET } from "../config";

export const register = async (req, res) => {
  const { username, email, password } = req.body;

  try {
    
    const usuarioEncontrado = await User.findOne({ email });
    
    if (usuarioEncontrado)
      return res.status(400).json(["el email ya esta en uso"]);


    const passwordHash = await bcryp.hash(password, 10);

    const nuevoUsuario = new User({
      username,
      email,
      password: passwordHash,
    });
    // logica para guardar este documento en la bd
    const usuarioGuardado = await nuevoUsuario.save();
    // utilizamos el token
    const token = await createAccesToken({ id: usuarioGuardado._id });
    //crear una cookie en el navegador o el cliente con express
    res.cookie("token", token);
    // respuesta al cliente
    res.json({
      email: usuarioGuardado.email,
      username: usuarioGuardado.username,
      id: usuarioGuardado.id,
    });
  } catch (error) {
    res.status(500).json([error.message]);
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    //guardamos en la variable el usuario o email que encontramos en la bd
    const userFound = await User.findOne({ email });
    //realizamos una validacion
    if (!userFound) return res.status(400).json(["Usuario no encontrado"]);

    //logica para verificar el password del usuario con el psw de la bd del email que se encuentra
    const isMatch = await bcryp.compare(password, userFound.password);
    //realizamos una validacion
    if (!isMatch) return res.status(400).json(["Contraseña incorrecta"]);

    //utilizamos el token
    const token = await createAccesToken({ id: userFound._id }); // se envia el id para que se cree como token
    //se crea una cooki que ya viene de express, para que se cree directamente la cooki en el navegador
    res.cookie("token", token);

    //respuesta al cliente
    res.json({
      email: userFound.email,
      username: userFound.username,
      id: userFound.id,
      createdAt: userFound.createdAt,
    });
  } catch (error) {
    res.status(400).json({message:error.message})
  }
}

export const logout = (req, res) => {
  res.cookie("token", "",{
    expires : new Date(0),
  });
  return res.sendStatus(200)
}

export const profile = async(req, res) => {
  const usuarioEncontrado = await User.findById(req.user.id)

  if(!usuarioEncontrado) return res.status(400).json(["usuario  no encontrado"]);

  return res.json({
    id: usuarioEncontrado._id,
    username: usuarioEncontrado.username,
    email:usuarioEncontrado.email,
  })
}
