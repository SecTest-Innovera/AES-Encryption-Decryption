import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class Decrypt {
	public static void main(String[] args) {
		if (args.length < 2) {
			System.out.println("Encrypt: java Decrypt 1 \"SecretKey\" \"IV\" \"data\"  ");
			System.out.println("Decrypt: java Decrypt 2 \"SecretKey\" \"IV\" \"data\"  ");

			return;
		}

        String islem = args[0];
        byte[] key = tobyte(args[1]);
        byte[] iv = tobyte(args[2]);
        String dirty = args[3];
        
        try {
        	System.out.println("Islem: " + islem);

        	if (islem.equals("1")) {
        		byte[] encrypted = encrypt(dirty.getBytes("UTF-8"), key, iv);
			
				System.out.println("Encrypted: " + Base64.getEncoder().encodeToString(encrypted));	
        	} else {
        		byte[] dirtybytes = Base64.getDecoder().decode(dirty);
				byte[] decrypted = decrypt(dirtybytes, key, iv);

				System.out.println("Decrypted: " + new String(decrypted, "UTF-8"));
        	}
        } catch (Exception e) {
        	System.out.println(e.toString());
        }
	}

	public static byte[] tobyte(String paramString) {
		try {
			byte[] arrayOfByte = new byte[16];
			byte[] array2 = paramString.getBytes("UTF-8");

			System.arraycopy(array2, 0, arrayOfByte, 0, Math.min(array2.length, arrayOfByte.length));

			return arrayOfByte;

		} catch (Exception e) {
			
		}

		byte[] ret = new byte[16];

		return ret;
	}

    public static byte[] encrypt(byte[] plainText, byte[] key,  byte[] iv) throws Exception {
        // Encrypt.
        Cipher cipherEncrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherEncrypt.init(1, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] encrypted = cipherEncrypt.doFinal(plainText);

        return encrypted;
    }

    public static byte[] decrypt(byte[] encryptedData, byte[] key, byte[] iv) throws Exception {
        // Decrypt.
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(2, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] decrypted = cipherDecrypt.doFinal(encryptedData);

        return decrypted;
    }
}
