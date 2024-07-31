# colores
green='\e[0;32m%-1s\e[m'

yarn create next-app $1 --ts --eslint --tailwind --src-dir --app --no-import-alias
cd $1

# Instalar dependencias
yarn add axios
yarn add zod

# Agregar configuración para trabajar con una API
printf $green "Desea agregar configuración para trabajar con una API? [y/n]: "
read -k1 add_api

if [[ $add_api == "y" ]]; then
    print ""
    next_api
fi

# Abrir VSCode
code .
