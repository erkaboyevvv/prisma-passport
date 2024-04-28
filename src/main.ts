import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const PORT = process.env.PORT || 3030
  app.use(cookieParser())
  app.useGlobalPipes(new ValidationPipe())
  await app.listen(PORT, () => {
    console.log(`http://localhost:${PORT}`);
  });

}
bootstrap();
