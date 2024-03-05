import { webcrypto } from "crypto";

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  const { privateKey, publicKey } = await webcrypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: "SHA-256" },
    },
    true,
    ["encrypt", "decrypt"]
  );
  return { publicKey, privateKey };
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey("spki", key);
  const exportedAsString = arrayBufferToBase64(exportedKey);
  return exportedAsString;
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
  key: webcrypto.CryptoKey | null
): Promise<string | null> {
  if (!key) return null;

  const exportedKey = await webcrypto.subtle.exportKey("pkcs8", key);
  const exportedAsString = arrayBufferToBase64(exportedKey);
  return exportedAsString;
}

// Import a base64 string public key to its native format
export async function importPubKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const publicKeyData = base64ToArrayBuffer(strKey);
  const importedKey = await webcrypto.subtle.importKey(
    "spki", // Format de la clé (SubjectPublicKeyInfo)
    publicKeyData,
    {
      name: "RSA-OAEP", // Algorithme de la clé (ici, RSA avec OAEP)
      hash: "SHA-256", // Fonction de hachage utilisée
    },
    true, // Extractable
    ["encrypt"] // Usage de la clé (ici, uniquement pour l'encryption)
  );
  return importedKey;
}

export async function importPrvKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const privateKeyData = base64ToArrayBuffer(strKey);
  const importedKey = await webcrypto.subtle.importKey(
    "pkcs8", // Format de la clé (PKCS #8)
    privateKeyData,
    {
      name: "RSA-OAEP", // Algorithme de la clé (ici, RSA avec OAEP)
      hash: "SHA-256", // Fonction de hachage utilisée
    },
    true, // Extractable
    ["decrypt"] // Usage de la clé (ici, uniquement pour le déchiffrement)
  );
  return importedKey;
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
  b64Data: string,
  strPublicKey: string
): Promise<string> {
  // Convertir la clé publique en format ArrayBuffer
  const publicKeyData = base64ToArrayBuffer(strPublicKey);
  // Importer la clé publique
  const publicKey = await importPubKey(strPublicKey);
  // Convertir les données du message en format ArrayBuffer
  const data = base64ToArrayBuffer(b64Data);
  // Chiffrer les données avec la clé publique importée
  const encryptedData = await webcrypto.subtle.encrypt(
    {
      name: "RSA-OAEP", // Algorithme de chiffrement RSA avec OAEP
    },
    publicKey,
    data
  );
  // Convertir les données chiffrées en format Base64
  const encryptedDataB64 = arrayBufferToBase64(encryptedData);
  return encryptedDataB64;
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(
  encryptedData: string,
  privateKey: webcrypto.CryptoKey
): Promise<string> {
  // Convert the encrypted data from Base64 string to ArrayBuffer
  const encryptedArrayBuffer = base64ToArrayBuffer(encryptedData);

  // Decrypt the data using the RSA private key
  const decryptedData = await webcrypto.subtle.decrypt(
    {
      name: "RSA-OAEP" // RSA decryption algorithm with OAEP padding
    },
    privateKey,
    encryptedArrayBuffer
  );

  // Convert the decrypted data from ArrayBuffer to string
  const decryptedText = new TextDecoder().decode(decryptedData);

  return decryptedText;
}

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  // Générer une clé symétrique aléatoire
  const key = await webcrypto.subtle.generateKey(
    {
      name: "AES-GCM", // Algorithme de chiffrement symétrique AES en mode GCM
      length: 256, // Longueur de la clé en bits (256 bits pour AES-256)
    },
    true, // Indiquer que la clé doit être extractible
    ["encrypt", "decrypt"] // Spécifier les opérations autorisées avec cette clé (chiffrement et déchiffrement)
  );
  return key;
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  // Exporter la clé symétrique sous forme de ArrayBuffer
  const keyData = await webcrypto.subtle.exportKey("raw", key);

  // Convertir l'ArrayBuffer en une chaîne de caractères base64
  const base64Key = Buffer.from(keyData).toString("base64");

  return base64Key;
}

// Import a base64 string format to its crypto native format
export async function importSymKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // Convertir la chaîne de caractères base64 en ArrayBuffer
  const keyData = Buffer.from(strKey, "base64");

  // Importer la clé à partir de l'ArrayBuffer
  const key = await webcrypto.subtle.importKey(
    "raw", // Format de clé : raw
    keyData, // Données de clé : ArrayBuffer
    { name: "AES-GCM" }, // Algorithme de clé : AES-GCM (ou l'algorithme utilisé pour générer la clé)
    true, // Extraitable : true (ou false selon les besoins)
    ["encrypt", "decrypt"] // Utilisations de la clé : encryption, decryption
  );

  return key;
}

// Encrypt a message using a symmetric key
export async function symEncrypt(
  key: webcrypto.CryptoKey,
  data: string
): Promise<string> {
  // Convertir la chaîne de caractères en ArrayBuffer
  const encodedData = new TextEncoder().encode(data);

  // Chiffrer les données avec la clé symétrique
  const encryptedData = await webcrypto.subtle.encrypt(
    {
      name: "AES-GCM", // Algorithme de chiffrement : AES-GCM (ou l'algorithme utilisé pour générer la clé)
      iv: crypto.getRandomValues(new Uint8Array(12)), // Initialisation vector (IV) aléatoire de 12 octets pour AES-GCM
    },
    key, // Clé symétrique
    encodedData // Données à chiffrer
  );

  // Convertir le résultat en base64
  const encryptedBase64 = Buffer.from(encryptedData).toString("base64");

  return encryptedBase64;
}

// Decrypt a message using a symmetric key
export async function symDecrypt(
  strKey: string,
  encryptedData: string
): Promise<string> {
  // Convertir la clé en format CryptoKey
  const key = await importSymKey(strKey);

  // Convertir les données chiffrées en ArrayBuffer
  const encryptedArrayBuffer = base64ToArrayBuffer(encryptedData);

  // Déchiffrer les données avec la clé symétrique
  const decryptedData = await webcrypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: encryptedArrayBuffer.slice(0, 12), // Utiliser les premiers 12 octets comme IV pour AES-GCM
    },
    key,
    encryptedArrayBuffer.slice(12) // Exclure les premiers 12 octets utilisés comme IV
  );

  // Convertir les données déchiffrées en chaîne de caractères
  const decryptedText = new TextDecoder().decode(decryptedData);

  return decryptedText;
}
