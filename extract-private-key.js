// Script to extract private key from GenLayer keystore
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import readline from 'readline';
import { fileURLToPath } from 'url';
import { keccak_256 } from '@noble/hashes/sha3.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const keystorePath = path.join(process.env.USERPROFILE, '.genlayer', 'keystores', 'authenticity-gate.json');

console.log('Reading keystore from:', keystorePath);

function decryptKeystore(keystore, password) {
  try {
    // GenLayer uses capital C "Crypto" field
    const cryptoData = keystore.Crypto || keystore.crypto;
    if (!cryptoData) {
      throw new Error('Invalid keystore format');
    }

    const kdfparams = cryptoData.kdfparams;
    const kdf = cryptoData.kdf;
    
    let derivedKey;
    if (kdf === 'scrypt') {
      // Use scrypt for key derivation
      derivedKey = crypto.scryptSync(
        Buffer.from(password),
        Buffer.from(kdfparams.salt, 'hex'),
        kdfparams.dklen,
        {
          N: kdfparams.n,
          r: kdfparams.r,
          p: kdfparams.p,
          maxmem: 256 * 1024 * 1024 // 256 MB
        }
      );
    } else if (kdf === 'pbkdf2') {
      // Fallback to pbkdf2
      derivedKey = crypto.pbkdf2Sync(
        Buffer.from(password),
        Buffer.from(kdfparams.salt, 'hex'),
        kdfparams.c,
        kdfparams.dklen,
        'sha256'
      );
    } else {
      throw new Error('Unsupported KDF: ' + kdf);
    }

    const ciphertext = Buffer.from(cryptoData.ciphertext, 'hex');
    
    // Verify MAC using keccak256 (Ethereum standard)
    const mac = Buffer.from(keccak_256(Buffer.concat([derivedKey.slice(16, 32), ciphertext]))).toString('hex');

    if (mac !== cryptoData.mac) {
      throw new Error('Invalid password - MAC verification failed');
    }

    // Decrypt the private key
    const decipher = crypto.createDecipheriv(
      cryptoData.cipher,
      derivedKey.slice(0, 16),
      Buffer.from(cryptoData.cipherparams.iv, 'hex')
    );

    const privateKey = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);

    return '0x' + privateKey.toString('hex');
  } catch (error) {
    throw new Error('Decryption failed: ' + error.message);
  }
}

try {
  const keystore = JSON.parse(fs.readFileSync(keystorePath, 'utf8'));
  
  console.log('\n✓ Keystore file found!');
  console.log('Address:', '0x' + (keystore.address || 'Not found'));
  
  rl.question('\nEnter your keystore password: ', (password) => {
    try {
      const privateKey = decryptKeystore(keystore, password);
      
      console.log('\n✓ Successfully decrypted!');
      console.log('\n==========================================');
      console.log('Your Private Key:');
      console.log(privateKey);
      console.log('==========================================\n');
      console.log('⚠️  Keep this private key secure!');
      console.log('Add it to your .env file as:');
      console.log(`GENLAYER_PRIVATE_KEY=${privateKey}`);
      
    } catch (error) {
      console.error('\n✗ Error:', error.message);
    }
    
    rl.close();
  });
  
} catch (error) {
  console.error('Error reading keystore:', error.message);
  rl.close();
}
