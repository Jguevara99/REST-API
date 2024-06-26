import { TOKEN_SECRET } from "../config"
import jwt from 'jsonwebtoken'

export function createAccesToken(payload){
    //objeto global de node 
    // promesa para utilizar el async await o peticiones asincronas
    return new Promise((resolve, reject) => {
        jwt.sign(
            payload,
            TOKEN_SECRET,
            {
                expiresIn: "1d",
            },
            (err, token) => {
                if(err) reject(err)
                    resolve(token)
            }
        )
    })
}