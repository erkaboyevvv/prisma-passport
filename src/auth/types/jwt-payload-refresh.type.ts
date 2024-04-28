import { JwtPayload } from './jwt-payload.type';

export type JwtPayloadWithRfreshToken = JwtPayload & { refreshToken: string };
