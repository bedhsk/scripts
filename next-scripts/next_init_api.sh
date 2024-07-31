# Ingresar credenciales de la api
printf "Ingrese la URL de la API: "
read API_URL

printf "Ingrese la API_KEY: "
read API_KEY

print "Está a punto de crear una card para la API"
printf "Ingrese el nombre de la card: "
read CARD_NAME

page=$(
  cat <<EOF
import axios from "axios";
import ${CARD_NAME} from "./${CARD_NAME}Card";
import ${CARD_NAME} from "@/components/${CARD_NAME}Card";

interface Props {

}

export default async function Home() {
  const response = await axios.get<Props[]>(
    process.env.NEXT_PUBLIC_API_URL ?? "",
    {
      params: {
        api_key: process.env.NEXT_PUBLIC_API_KEY,
        count: 3,
      },
    }
  );

  return (
    <main>
      <h1>Listado de fotografías de la NASA</h1>
      <div className="flex flex-row">
        {response.data.map((photo: Props) => (
          <${CARD_NAME}Card />
        ))}
      </div>
    </main>
  );
}
EOF
)

card=$(
  cat <<EOF
import Image from "next/image";

interface Props {
  title: string;
  url: string;
  date: string;
  explanation: string;
}

export default function User({ title, url }: Props) {
  return (
    <div className="mx-2 max-w-sm bg-white border border-gray-200 rounded-lg shadow dark:bg-gray-800 dark:border-gray-700">
      <Image
        className="rounded-t-lg"
        src={url}
        alt={title}
        height={500}
        width={500}
      />
      <div className="p-5">
        <p className="mb-2 text-2xl font-bold tracking-tight text-gray-900 dark:text-white">
          {/* {title} */}
        </p>
        <p className="mb-3 font-normal text-gray-700 dark:text-gray-400">
          {/* {explanation} */}
        </p>
        {/* <p>{date}</p> */}
      </div>
    </div>
  );
}
EOF
)

archivo_env_local=$(
  cat <<EOF
NEXT_PUBLIC_API_URL=$API_URL
NEXT_PUBLIC_API_KEY=$API_KEY
EOF
)

env=$(
  cat <<EOF
import { z } from "zod";

const schema = z.object({
  NEXT_PUBLIC_API_URL: z.string(),
  NEXT_PUBLIC_API_KEY: z.string(),
});

export const parsedEnv = schema.parse(process.env);
EOF
)

next_config=$(
  cat <<EOF
/** @type {import('next').NextConfig} */
const nextConfig = {
  // images: {
  //   remotePatterns: [
  //     {
  //       protocol: "",
  //       hostname: "",
  //       pathname: "",
  //     },
  //   ],
  // },
};

export default nextConfig;
EOF
)

mkdir -p "./src/components"

printf "%s\n" "$archivo_env_local" >".env.local"
printf "%s\n" "$card" >"./src/components/${CARD_NAME}Card.tsx"
printf "%s\n" "$env" >"env.ts"
printf "%s\n" "$next_config" >"next.config.mjs"
printf "%s\n" "$page" >"./src/app/page.tsx"
