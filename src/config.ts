import dotenv from "dotenv";

dotenv.config();

function required(name: string): string {
  const v = process.env[name];
  if (!v || !v.trim()) {
    throw new Error(`missing required env var: ${name}`);
  }
  return v.trim();
}

export const config = {
  databaseUrl: required("DATABASE_URL"),
  jwtSecret: required("NC_JWT_SECRET"),
  masterKeyBase64: required("NC_MASTER_KEY_BASE64"),
  baseUrl: process.env.NC_BASE_URL?.trim() || "http://127.0.0.1:3000",
  docker: {
    openclawImage: process.env.OPENCLAW_IMAGE?.trim() || "openclaw:local",
    network: process.env.NC_DOCKER_NETWORK?.trim() || "nc-internal",
    openclawPort: Number(process.env.NC_OPENCLAW_PORT || "18789"),
    dataMountPath: process.env.NC_OPENCLAW_DATA_MOUNT?.trim() || "/data",
  },
};

