import crypto from "crypto" // this man is entirely built into nodejs

export function hashPassword(password: string, salt: string): Promise<string> {
  return new Promise((resolve, reject) => {

    // we normalize the password to make sure that there is no weird characters in the password !
    
    crypto.scrypt(password.normalize(), salt, 64, (error, hash) => {   // the modern equivalnt to bcrypt OH yeah
      if (error) reject(error)

      resolve(hash.toString("hex").normalize())
    })
  })
}

export async function comparePasswords({
  password,
  salt,
  hashedPassword,
}: {
  password: string
  salt: string
  hashedPassword: string
}) {
  const inputHashedPassword = await hashPassword(password, salt)

  return crypto.timingSafeEqual(
    Buffer.from(inputHashedPassword, "hex"),
    Buffer.from(hashedPassword, "hex")
  )
}

export function generateSalt() {
  return crypto.randomBytes(16).toString("hex").normalize()
}
