# colores
green='\e[0;32m%-1s\e[m'

instalar_dependencias() {
  # Autorización y autenticación
  yarn add bcrypt
  yarn add @nestjs/passport passport passport-local
  yarn add @nestjs/jwt
  yarn add passport-jwt
  # Dependencias de desarrollador
  yarn add -D @types/bcrypt
  yarn add -D @types/passport-local
  yarn add -D @types/passport-jwt
}

instalar_dependencias

# Generar módulo de autenticaciónes
printf $green "Desea asignar otro nombre al módulo de autenticación? [y/n]: "
read -k1 respuesta

if [[ $respuesta == "y" ]]; then
  printf "\nIngrese el nombre del módulo de autenticación: "
  read AUTH_MODULE_NAME
else
  printf "\n"
  AUTH_MODULE_NAME="auth"
fi

nest g module $AUTH_MODULE_NAME --no-spec
nest g controller $AUTH_MODULE_NAME --no-spec
nest g service $AUTH_MODULE_NAME --no-spec

# Generar módulo de autenticaciónes
printf $green "Desea asignar otro nombre al módulo de usuarios? [y/n]: "
read -k1 respuesta

if [[ $respuesta == "y" ]]; then
  printf "\nIngrese el nombre del módulo de autenticación: "
  read USERS_MODULE_NAME
else
  printf "\n"
  USERS_MODULE_NAME="users"
fi

USER_MODULE_NAME="${USERS_MODULE_NAME%?}"

USER=$USER_MODULE_NAME
primera_letra_mayuscula=$(echo "${USER:0:1}" | tr '[:lower:]' '[:upper:]')
resto_de_USER="${USER:1}"
USER="${primera_letra_mayuscula}${resto_de_USER}"

nest g module $USERS_MODULE_NAME --no-spec
nest g controller $USERS_MODULE_NAME --no-spec
nest g service $USERS_MODULE_NAME --no-spec

# ! Variables para generar archivos de users
# Modificar manualmente en caso de haber asignado otro nombre
users_service=$(
  cat <<EOF
import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Create${USER}Dto } from './dto/create-$USER_MODULE_NAME.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Update${USER}Dto } from './dto/update-$USER_MODULE_NAME.dto';
import $USER from './entities/$USER_MODULE_NAME.entity';

@Injectable()
export class ${USER}sService {
  constructor(
    @InjectRepository(${USER})
    private readonly ${USERS_MODULE_NAME}Repository: Repository<${USER}>,
  ) {}

  create(new_${USER_MODULE_NAME}: Create${USER}Dto) {
    if (new_${USER_MODULE_NAME}.name === undefined) {
      throw new BadRequestException('Name is required');
    }

    if (new_${USER_MODULE_NAME}.password === undefined) {
      throw new BadRequestException('Password is required');
    }

    const ${USER_MODULE_NAME} = this.${USERS_MODULE_NAME}Repository.create(new_${USER_MODULE_NAME});
    return this.${USERS_MODULE_NAME}Repository.save(${USER_MODULE_NAME});
  }

  findAll() {
    return this.${USERS_MODULE_NAME}Repository.find();
  }

  async findOne(id: number): Promise<${USER}> {
    const record = await this.${USERS_MODULE_NAME}Repository.findOne({
      where: { id },
    });

    if (!record) {
      throw new NotFoundException(\`${USER} #\${id} not found\`);
    }

    return record;
  }

  async findOneByEmail(email: string): Promise<${USER}> {
    return await this.${USERS_MODULE_NAME}Repository.findOne({
      where: { email },
    });
  }

  async update(id: number, update_${USER_MODULE_NAME}: Update${USER}Dto) {
    const ${USER_MODULE_NAME} = await this.findOne(id);
    this.${USERS_MODULE_NAME}Repository.merge(${USER_MODULE_NAME}, update_${USER_MODULE_NAME});
    return this.${USERS_MODULE_NAME}Repository.save(${USER_MODULE_NAME});
  }

  async remove(id: number) {
    const ${USER_MODULE_NAME} = await this.findOne(id);
    return this.${USERS_MODULE_NAME}Repository.remove(${USER_MODULE_NAME});
  }
}
EOF
)

users_module=$(
  cat <<EOF
import { Module } from '@nestjs/common';
import { ${USER}sService } from './${USERS_MODULE_NAME}.service';
import { ${USER}sController } from './${USERS_MODULE_NAME}.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import ${USER} from './entities/${USER_MODULE_NAME}.entity';
import { APP_GUARD } from '@nestjs/core';
import { JwtGuard } from 'src/auth/guards/jwt.guard';

@Module({
  imports: [TypeOrmModule.forFeature([${USER}])],
  controllers: [${USER}sController],
  providers: [
    ${USER}sService,
    {
      provide: APP_GUARD,
      useClass: JwtGuard,
    },
  ],
  exports: [${USER}sService],
})
export class ${USER}sModule {}
EOF
)

users_controller=$(
  cat <<EOF
import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
} from '@nestjs/common';
import { ApiCreatedResponse, ApiTags } from '@nestjs/swagger';
import { Create${USER}Dto } from './dto/create-${USER_MODULE_NAME}.dto';
import { IsPublic } from './common/is-public.decorator';
import { ${USER}sService } from './${USERS_MODULE_NAME}.service';
import ${USER} from './entities/${USER_MODULE_NAME}.entity';

@ApiTags('${USER}s')
@Controller('${USERS_MODULE_NAME}')
export class ${USER}sController {
  constructor(private readonly ${USER_MODULE_NAME}Service: ${USER}sService) {}

  @Post('sing-up')
  @IsPublic()
  @ApiCreatedResponse({
    description: 'Este endpoint sirve para crear nuevos usuarios.',
    type: ${USER},
  })
  @HttpCode(HttpStatus.CREATED)
  create(@Body() body: Create${USER}Dto) {
    return this.${USER_MODULE_NAME}Service.create(body);
  }

  @Get()
  @IsPublic()
  @ApiCreatedResponse({
    description: 'Obtiene todos los usuarios.',
    type: ${USER},
    isArray: true,
  })
  findAll() {
    const records = this.${USER_MODULE_NAME}Service.findAll();
    return records;
  }

  @Get(':id')
  @ApiCreatedResponse({
    description: 'Obtiene un usuario por su id.',
    type: ${USER},
  })
  findOne(@Param('id') id: number) {
    return this.${USER_MODULE_NAME}Service.findOne(id);
  }

  @Patch(':id')
  @ApiCreatedResponse({
    description: 'Actualiza un usuario.',
    type: ${USER},
  })
  update(@Param('id') id: number, @Body() body) {
    return this.${USER_MODULE_NAME}Service.update(id, body);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiCreatedResponse({
    description: 'Elimina un usuario.',
  })
  destroy(@Param('id') id: number) {
    return this.${USER_MODULE_NAME}Service.remove(id);
  }
}
EOF
)

users_entity=$(
  cat <<EOF
import { ApiProperty } from '@nestjs/swagger';
import { BeforeInsert, Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import * as bcrypt from 'bcrypt';

@Entity('${USERS_MODULE_NAME}')
class ${USER} {
  @PrimaryGeneratedColumn()
  @ApiProperty()
  id: number;

  @Column({ type: 'varchar', length: 255 })
  @ApiProperty()
  name: string;

  @Column({ type: 'varchar', length: 255 })
  @ApiProperty()
  email: string;

  @Column({ type: 'varchar', default: '' })
  @ApiProperty()
  password: string;

  // Encriptar contraseña antes de insertar
  @BeforeInsert()
  async hashPassword() {
    const saltOrRounds = 10;
    const hash = await bcrypt.hash(this.password, saltOrRounds);
    this.password = hash;
  }
}

export default ${USER};

EOF
)

users_create_dto=$(
  cat <<EOF
import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MaxLength, MinLength } from 'class-validator';

export class Create${USER}Dto {
  @MinLength(3)
  @MaxLength(255)
  @IsString()
  @ApiProperty({
    description: 'Nombre del usuario',
    example: 'John Doe',
  })
  name: string;

  @MinLength(4)
  @IsEmail()
  @ApiProperty({
    description: 'Correo electrónico del usuario',
    example: 'example@gmail.com',
  })
  email: string;

  @IsString()
  @ApiProperty({
    description: 'Contraseña del usuario',
    example: 'password123',
  })
  password: string;
}
EOF
)

users_update_dto=$(
  cat <<EOF
import { PartialType } from '@nestjs/mapped-types';
import { Create${USER}Dto } from './create-${USER_MODULE_NAME}.dto';

export class Update${USER}Dto extends PartialType(Create${USER}Dto) {}
EOF
)

# ! Variables para generar archivos de users
auth_service=$(
  cat <<EOF
import { Injectable, UnauthorizedException } from '@nestjs/common';
import ${USER} from 'src/${USERS_MODULE_NAME}/entities/${USER_MODULE_NAME}.entity';
import { ${USER}sService } from 'src/${USERS_MODULE_NAME}/${USERS_MODULE_NAME}.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private readonly ${USERS_MODULE_NAME}Service: ${USER}sService) {}

  async singIn(email: string, password: string): Promise<${USER} | undefined> {
    const ${USER_MODULE_NAME} = await this.${USERS_MODULE_NAME}Service.findOneByEmail(email);

    if (${USER_MODULE_NAME} === undefined) {
      throw new UnauthorizedException();
    }

    const isMatch = await bcrypt.compare(password, ${USER_MODULE_NAME}.password);

    if (!isMatch) {
      throw new UnauthorizedException();
    }

    return ${USER_MODULE_NAME};
  }
}
EOF
)

auth_module=$(
  cat <<EOF
import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { LocalStrategy } from './strategies/local.strategy';
import { ${USER}sModule } from 'src/${USERS_MODULE_NAME}/${USERS_MODULE_NAME}.module';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtStrategy } from './strategies/jwt.strategy';

@Module({
  controllers: [AuthController],
  providers: [AuthService, LocalStrategy, JwtStrategy],
  imports: [
    ${USER}sModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (ConfigService: ConfigService) => {
        return {
          secret: ConfigService.get('JWT_SECRET'),
          signOptions: {},
        };
      },
    }),
  ],
})
export class AuthModule {}
EOF
)

auth_controller=$(
  cat <<EOF
import {
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiCreatedResponse, ApiTags } from '@nestjs/swagger';
import { IsPublic } from 'src/${USERS_MODULE_NAME}/common/is-public.decorator';
import { JwtService } from '@nestjs/jwt';
import { LocalGuard } from './guards/local.guard';
import { Request } from 'express';
import ${USER} from 'src/${USERS_MODULE_NAME}/entities/${USER_MODULE_NAME}.entity';

@ApiTags('Authentications')
@Controller('auth')
export class AuthController {
  constructor(private readonly jwtService: JwtService) {}

  @HttpCode(HttpStatus.CREATED)
  @Post('login')
  @IsPublic()
  @ApiCreatedResponse({
    status: 201,
    description: 'Inicia sesión y devuelve un token de acceso.',
  })
  @UseGuards(LocalGuard)
  async login(@Req() request: Request) {
    const ${USER_MODULE_NAME} = request.user as ${USER};

    const payload = {
      sub: ${USER_MODULE_NAME}.id,
    };

    const accessToken = await this.jwtService.signAsync(payload);
    return {
      access_token: accessToken,
    };
  }
}
EOF
)

auth_sing_in_dto=$(
  cat <<EOF
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export default class SignInDto {
  @IsString()
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
EOF
)

jwt_guard=$(
  cat <<EOF
import { ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { Observable } from 'rxjs';

@Injectable()
export class JwtGuard extends AuthGuard('jwt') {
  constructor(private readonly reflector: Reflector) {
    super();
  }

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>('isPublic', [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    return super.canActivate(context);
  }
}
EOF
)

local_guard=$(
  cat <<EOF
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalGuard extends AuthGuard('local') {}
EOF
)

jwt_strategy=$(
  cat <<EOF
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ${USER}sService } from 'src/${USERS_MODULE_NAME}/${USERS_MODULE_NAME}.service';

type Payload = {
  sub: number;
};

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly ${USER_MODULE_NAME}Service: ${USER}sService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      expiresIn: '3d',
      secretOrKey: process.env.JWT_SECRET,
    });
  }

  async validate(payload: Payload) {
    return await this.${USER_MODULE_NAME}Service.findOne(payload.sub);
  }
}

EOF
)

local_strategy=$(
  cat <<EOF
import { Injectable } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      usernameField: 'email',
    });
  }

  async validate(username: string, password: string) {
    return await this.authService.singIn(username, password);
  }
}
EOF
)

is_public=$(
  cat <<EOF
import { SetMetadata } from '@nestjs/common';

export const IsPublic = () => SetMetadata('isPublic', true);
EOF
)

# ! Generar archivos para usuarios
mkdir -p "./src/$USERS_MODULE_NAME/entities"
mkdir -p "./src/$USERS_MODULE_NAME/dto"
mkdir -p "./src/$USERS_MODULE_NAME/common"

touch "./src/$USERS_MODULE_NAME/entities/$USER_MODULE_NAME.entity.ts"
touch "./src/$USERS_MODULE_NAME/dto/create-$USER_MODULE_NAME.dto.ts"
touch "./src/$USERS_MODULE_NAME/dto/update-$USER_MODULE_NAME.dto.ts"
touch "./src/$USERS_MODULE_NAME/common/is-public.decorator.ts"

printf "%s\n" "$users_service" >"./src/$USERS_MODULE_NAME/$USERS_MODULE_NAME.service.ts"
printf "%s\n" "$users_module" >"./src/$USERS_MODULE_NAME/$USERS_MODULE_NAME.module.ts"
printf "%s\n" "$users_controller" >"./src/$USERS_MODULE_NAME/$USERS_MODULE_NAME.controller.ts"
printf "%s\n" "$users_entity" >"./src/$USERS_MODULE_NAME/entities/$USER_MODULE_NAME.entity.ts"
printf "%s\n" "$users_create_dto" >"./src/$USERS_MODULE_NAME/dto/create-${USER_MODULE_NAME}.dto.ts"
printf "%s\n" "$users_update_dto" >"./src/$USERS_MODULE_NAME/dto/update-${USER_MODULE_NAME}.dto.ts"
printf "%s\n" "$is_public" >"./src/$USERS_MODULE_NAME/common/is-public.decorator.ts"

# ! Generar archivos para autenticación
mkdir -p "./src/$AUTH_MODULE_NAME/guards"
mkdir -p "./src/$AUTH_MODULE_NAME/strategies"

touch "./src/$AUTH_MODULE_NAME/guards/jwt.guard.ts"
touch "./src/$AUTH_MODULE_NAME/guards/local.guard.ts"
touch "./src/$AUTH_MODULE_NAME/strategies/jwt.strategy.ts"
touch "./src/$AUTH_MODULE_NAME/strategies/local.strategy.ts"

printf "%s\n" "$auth_service" >"./src/$AUTH_MODULE_NAME/$AUTH_MODULE_NAME.service.ts"
printf "%s\n" "$auth_module" >"./src/$AUTH_MODULE_NAME/$AUTH_MODULE_NAME.module.ts"
printf "%s\n" "$auth_controller" >"./src/$AUTH_MODULE_NAME/$AUTH_MODULE_NAME.controller.ts"
printf "%s\n" "$auth_sing_in_dto" >"./src/$AUTH_MODULE_NAME/dto/sign-in.dto.ts"
printf "%s\n" "$jwt_guard" >"./src/$AUTH_MODULE_NAME/guards/jwt.guard.ts"
printf "%s\n" "$local_guard" >"./src/$AUTH_MODULE_NAME/guards/local.guard.ts"
printf "%s\n" "$jwt_strategy" >"./src/$AUTH_MODULE_NAME/strategies/jwt.strategy.ts"
printf "%s\n" "$local_strategy" >"./src/$AUTH_MODULE_NAME/strategies/local.strategy.ts"

git add .
git commit -m "Módulo de usuarios y autenticación añadidos y funcionando."

# Generar migraciones y correrlas
yarn migration:generate src/migrations/init_auth
yarn migration:run
