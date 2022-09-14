import { Injectable } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcrypt'

@Injectable()
export class AuthService {
    constructor(private userService: UserService){}

    async validateUser(email: string, password: string) {
        const user = await this.userService.findByEmail(email)

        if(user){
            // checar se a senha informada corresponde a hash que está no banco
            const isPasswordValid = await bcrypt.compare(password, user.password)
            
            if(isPasswordValid){
                return {
                    ...user,
                    password: undefined
                }
            }
        } 

        throw new Error('invalid credentials')
    }
}
