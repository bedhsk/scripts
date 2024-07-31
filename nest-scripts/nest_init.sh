#!/bin/zsh

# colores
green='\e[0;32m%-1s\e[m'

# Utilizar la versión 18.18.0 de Nest
nvm use v18.18.0

# Función para los commits
commit() {
  git add .
  git commit -m "$1"
}

# Iniciar nuevo proyecto en nest
printf "Ingrese el nombre del proyecto: "
read PROJECT_NAME

# Crear el proyecto en NestJS
nest new $PROJECT_NAME

# Cambiar al directorio del proyecto
cd $PROJECT_NAME

#! Comandos iniciales de Git
# Cambiar el nombre de la rama a 'main'
git branch -M main

# Agregar todas las modificaciones y hacer un commit inicial
commit "First commit. Initial setup of the project."

# Pedir al usuario el enlace del repositorio remoto
printf $green "¿Desea ingresar un repositorio remoto? [y/n]: "
read -k1 have_remote_repo

# Verificar la respuesta
if [[ $have_remote_repo == "y" ]]; then
  # El usuario desea agregar un repositorio remoto
  printf "\nIngrese el enlace SSH del repositorio remoto: "
  read REMOTE_REPO

  # Agregar el repositorio remoto y hacer push
  git remote add origin $REMOTE_REPO
  git push -f origin main
else
  # El usuario no desea agregar un repositorio remoto
  print "\nNo se agregó un repositorio remoto."
fi

# * Instalar las dependencias del proyecto NestJS *
instalar_dependencias() {
  yarn add class-validator class-transformer
  yarn add @nestjs/typeorm typeorm pg
  yarn add @nestjs/mapped-types
  yarn add @nestjs/config
  yarn add @hapi/joi
  yarn add @nestjs/swagger
  # Dependencias de desarrollador
  yarn add -D @types/validator
  yarn add -D @types/hapi__joi
}

instalar_dependencias

printf $green "¿Desea asignar nombre a las variables de la DB? [y/n]: "
read -k1 respuesta
if [[ $respuesta == "y" ]]; then
  printf "\nIngrese el nombre de la base de datos: "
  read DB_NAME
  printf "Ingrese el nombre de usuario: "
  read DB_USER
  printf "Ingrese la contraseña: "
  read DB_PASS
else
  DB_NAME="url2024"
  DB_USER="url"
  DB_PASS="url.2024"
  printf "\n"
fi

# * Crear los archivos de configuración *
archivo_env=$(
  cat <<EOF
DB_HOST=
DB_PORT=
DB_NAME=
DB_USER=
DB_PASS=
JWT_SECRET=
EOF
)

archivo_env_local=$(
  cat <<EOF
DB_HOST=localhost
DB_PORT=5432
DB_USER=$DB_USER
DB_PASS=$DB_PASS
DB_NAME=$DB_NAME
JWT_SECRET='secret2309'
EOF
)

archivo_app_module=$(
  cat <<EOF
import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import * as Joi from '@hapi/joi';

@Module({
  imports: [
    ConfigModule.forRoot({
      envFilePath: '.env.local',
      validationSchema: Joi.object({
        DB_HOST: Joi.string().required(),
        DB_PORT: Joi.number().default(5432),
        DB_NAME: Joi.string().required(),
        DB_USER: Joi.string().required(),
        DB_PASS: Joi.string().required(),
        JWT_SECRET: Joi.string().required(),
      }),
    }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.DB_HOST,
      port: +process.env.DB_PORT,
      username: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
      autoLoadEntities: true,
      synchronize: false,
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
EOF
)

archivo_docker_compose=$(
  cat <<EOF
version: "3"
services:
  db:
    image: "postgres:latest"
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_USER=$DB_USER
      - POSTGRES_PASSWORD=$DB_PASS
      - POSTGRES_DB=$DB_NAME
EOF
)

archivo_typeorm_config=$(
  cat <<EOF
import { DataSource } from 'typeorm';

export const dataSource: DataSource = new DataSource({
  type: 'postgres',
  host: 'localhost',
  port: 5432,
  username: '${DB_USER}',
  password: '${DB_PASS}',
  database: '${DB_NAME}',
  synchronize: false,
  entities: ['src/**/*.entity{.ts, .js}'],
  migrations: ['./src/migrations/*.ts'],
});
EOF
)

archivo_main=$(
  cat <<EOF
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      // Esto es para que no se envien datos que no esten en el DTO
      whitelist: true,
      forbidNonWhitelisted: true,
      // Esto es para que los datos que se envien se transformen a los tipos de datos que se estan esperando
      transform: true,
    }),
  );
  const config = new DocumentBuilder()
    .setTitle('NestJS API')
    .setDescription('Una descripción de la API')
    .setVersion('1.0')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);
  await app.listen(3000);
}
bootstrap();
EOF
)

# ! Asignar nombre al archvio de configuración de TypeORM
printf $green "¿Desea asignar un nombre al archivo de configuración de TypeORM? [y/n]:"
# Leer la entrada del usuario
read -k1 respuesta

# Verificar la respuesta
if [[ $respuesta == "y" ]]; then
  # El usuario desea asignar el nombre del archivo de configuración de TypeORM
  printf "\nIngrese el nombre que tendrá el archivo: "
  read typeorm_config
  print "\nEl archivo de configuración de TypeORM será: $typeorm_config"
else
  # El usuario no desea asignar el nombre del archivo de configuración de TypeORM
  typeorm_config="typeorm.config.ts"
  print "\nEl archivo de configuración de TypeORM será: $typeorm_config"
fi

# ! Generar los archivos env, env local y typeorm_config
printf "%s\n" "$archivo_env" >".env"
printf "%s\n" "$archivo_env_local" >".env.local"
commit "Configuración de archivos .env y .env.local"
printf "%s\n" "$archivo_docker_compose" >"docker-compose.yml"
printf "%s\n" "$archivo_typeorm_config" >"$typeorm_config"
commit "Configuración de archivos docker-compose.yml y \$typeorm_config"

# ! Configuración básica del app.module
rm ./src/app.module.ts
printf "%s\n" "$archivo_app_module" >"./src/app.module.ts"
commit "Configuración básica del archivo app.module.ts"

# ! Modificar el archivo package.json para agregar las líneas al final de la sección "scripts"
jq --arg typeorm_conf "$typeorm_config" '.scripts += {
  "typeorm": "ts-node -r tsconfig-paths/register ./node_modules/.bin/typeorm",
  "migration:generate": "npm run typeorm migration:generate -- -d ./\($typeorm_conf)",
  "migration:run": "npm run typeorm migration:run -- -d \($typeorm_conf)",
  "migration:revert": "npm run typeorm migration:revert -- -d \($typeorm_conf)",
  "rsd": "yarn run start:dev"
}' package.json >tmpfile.json && mv tmpfile.json package.json
commit "Configuración de scripts en el archivo package.json"

# ! Crear el archivo main.ts para funcionar con Swagger
printf "%s\n" "$archivo_main" >"./src/main.ts"
commit "Configuración de archivo main.ts para funcionar con Swagger"

# ! Agregar módulo de autenticación
printf $green "¿Desea agregar el módulo de autenticación? [y/n]: "
read -k1 respuesta

if [[ $respuesta == "y" ]]; then
  print ""
  nest_auth
fi

# Iniciar DB con Docker
docker-compose up -d

# Abrir VSCode
code .
