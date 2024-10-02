const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const app = express();

// Use a porta fornecida pelo ambiente do Replit ou 3000 para ambientes locais
const port = process.env.PORT || 3000;

// Defina uma chave de API de exemplo
const API_KEY = "1234567890abcdef";

// Middleware para permitir o parsing de JSON nas requisições
app.use(express.json());

// Habilita o CORS para todas as rotas
app.use(cors());

// Middleware de autenticação de chave de API
const authenticateAPIKey = (req, res, next) => {
  const apiKey = req.header("x-api-key");
  if (!apiKey) {
    return res.status(401).json({ message: "Chave de API ausente." });
  }
  if (apiKey !== API_KEY) {
    return res.status(403).json({ message: "Chave de API inválida." });
  }
  next();
};

// Aplicando o middleware de autenticação em todas as rotas da API
app.use("/api", authenticateAPIKey);

// Configurações de criptografia
const algoritmo = "aes-256-cbc";
const generateKeyAndIV = (key) => {
  return {
    key: crypto.createHash("sha256").update(key).digest(),
    iv: crypto.randomBytes(16),
  };
};

// Endpoint para criptografar uma mensagem
app.post("/api/encrypt", (req, res) => {
  try {
    const { message } = req.body;
    const { key: encryptionKey, iv } = generateKeyAndIV(API_KEY);

    const cipher = crypto.createCipheriv(algoritmo, encryptionKey, iv);
    let encrypted = cipher.update(message, "utf8", "hex");
    encrypted += cipher.final("hex");

    res.status(200).json({ encryptedData: encrypted, iv: iv.toString("hex") });
  } catch (error) {
    res.status(500).json({ message: "Erro ao criptografar a mensagem." });
  }
});

// Endpoint para descriptografar uma mensagem
app.post("/api/decrypt", (req, res) => {
  try {
    const { encryptedData, iv } = req.body;
    const { key: decryptionKey } = generateKeyAndIV(API_KEY);

    const decipher = crypto.createDecipheriv(
      algoritmo,
      decryptionKey,
      Buffer.from(iv, "hex"),
    );
    let decrypted = decipher.update(encryptedData, "hex", "utf8");
    decrypted += decipher.final("utf8");

    res.status(200).json({ decryptedMessage: decrypted });
  } catch (error) {
    res.status(500).json({ message: "Erro ao descriptografar a mensagem." });
  }
});

// Inicia o servidor
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});