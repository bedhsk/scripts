blue='\e[1;34m%-1s\e[m'
green='\e[0;32m%-1s\e[m'
purple='\e[0;35m%-1s\e[m'
red='\e[0;31m%-1s\e[m'
red_blod='\e[1;31m%-1s\e[m'

USERS_MODULE_NAME="users"
USER_MODULE_NAME="${USERS_MODULE_NAME%?}"

USER=$USER_MODULE_NAME
primera_letra_mayuscula=$(echo "${USER:0:1}" | tr '[:lower:]' '[:upper:]')
resto_de_USER="${USER:1}"
USER="${primera_letra_mayuscula}${resto_de_USER}"
echo $USER # Imprime "Users"

printf $blue "This is text"
printf "\n"$green "Th"
printf "\n"$purple "This is text"
printf "\n"$red "Hola Rojo"
printf "\n"$red_blod "Hola Rojo"
print "\nfin"
