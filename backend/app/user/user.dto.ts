
import { type BaseSchema } from "../common/dto/base.dto";

export interface IUser extends BaseSchema {
        name: string;
        email: string;
        role: "USER" | "ADMIN";
        password: string;
        refreshToken: string;
        resetPasswordToken: string;
}

export interface Payload {
        _id: string;
        name: string;
        email: string;
        role: 'USER' | 'ADMIN';
}