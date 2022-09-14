import { Injectable } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcrypt'
import { User } from '@prisma/client';
import { UserPayload } from './models/UserPayload';
import { JwtService } from '@nestjs/jwt';
import { UserToken } from './models/UserToken';

@Injectable()
export class AuthService {
    constructor(
        private userService: UserService, 
        private jwtService: JwtService
    ){}

    login(user: User): UserToken {
        // transforma um user em um JWT
        const payload: UserPayload = {
            sub: user.id,
            email: user.email,
            name: user.name
        }

        const jwtToken = this.jwtService.sign(payload)

        return {
            access_token: jwtToken
        }
    }

    async validateUser(email: string, password: string) {
        const user = await this.userService.findByEmail(email)

        if(user){
            // checar se a senha informada corresponde a hash que está no banco
            const isPasswordValid = await bcrypt.compare(password, user.password)
            
            if(isPasswordValid) return {...user, password: undefined}
        } 

        throw new Error('invalid credentials')
    }

}
