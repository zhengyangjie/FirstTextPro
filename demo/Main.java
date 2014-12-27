 

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by jsand on 8/14/14.
 */
public class Main {
	public static void main(String[] args) throws Exception {
		final String src = "123";
		final String key = "key";

		System.out.println("string:" + src);
		System.out.println("key:" + key);
		System.out.println();

		System.out.println("SHA256:" + getSHA256(src));
		System.out.println("HmacSHA1:" + getHmacSHA1(src, key));
		System.out.println("MD5:" + getMD5(src));
		System.out.println("MD5withKey:" + getMD5WithKey(src, key));
		System.out.println();

		String[] keys = generateRSAKeyPair();
		String encStr = encryptRSA(src, keys[1]);
		System.out.println("RSA encrypted:" + encStr);
		System.out.println("RSA decrypted:" + decryptRSA(encStr, keys[0]));
		System.out.println();

		String desStr = encryptDES(src, key);
		System.out.println("DES encrypted:" + desStr);
		System.out.println("DES decrypted:" + decryptDES(desStr, key));
		System.out.println();

		String aesStr = encryptAES(src, key);
		System.out.println("AES encrypted:" + aesStr);
		System.out.println("AES decrypted:" + decryptAES(aesStr, key));
	}

	public static String getSHA256(String input) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(input.getBytes("UTF-8"));

		BigInteger bi = new BigInteger(1, md.digest());
		return String.format("%1$064x", bi);
	}

	public static String getHmacSHA1(String input, String key) throws Exception {
		Mac mac = Mac.getInstance("HmacSHA1");
		SecretKeySpec secret = new SecretKeySpec(key.getBytes("UTF-8"), mac.getAlgorithm());
		mac.init(secret);
		return Base64.encode(mac.doFinal(input.getBytes("UTF-8")), true);
	}

	public static String getMD5(String input) throws Exception {
		MessageDigest m = MessageDigest.getInstance("MD5");
		m.update(input.getBytes("UTF-8"));

		BigInteger bi = new BigInteger(1, m.digest());
		return String.format("%1$032x", bi);
	}

	public static String getMD5WithKey(String input, String key) throws Exception {
		return getMD5(input + key);
	}

	private static Key getSecKey(String key, String algorithm) throws Exception {
		String md5 = getMD5(key);
		int keyLength = "AES".equalsIgnoreCase(algorithm) ? 16 : 8;
		SecretKeySpec keySpec = new SecretKeySpec(md5.getBytes(), 0, keyLength, algorithm);
		return keySpec;
	}

	public static String encryptDES(String input, String key) throws Exception {
		Key desKey = getSecKey(key, "DES");

		Cipher enCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		enCipher.init(Cipher.ENCRYPT_MODE, desKey);
		byte[] pasByte = enCipher.doFinal(input.getBytes("UTF-8"));
		return Base64.encode(pasByte, true);
	}

	public static String decryptDES(String input, String key) throws Exception {
		Key desKey = getSecKey(key, "DES");

		Cipher enCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
		enCipher.init(Cipher.DECRYPT_MODE, desKey);
		byte[] pasByte = enCipher.doFinal(Base64.decode(input));
		return new String(pasByte, "UTF-8");
	}

	public static String encryptAES(String input, String key) throws Exception {
		Key aesKey = getSecKey(key, "AES");

		Cipher enCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		byte[] iv = new byte[16];
		IvParameterSpec ivspec = new IvParameterSpec(iv);

		enCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivspec);
		byte[] pasByte = enCipher.doFinal(input.getBytes("UTF-8"));
		return Base64.encode(pasByte, true);
	}

	public static String decryptAES(String input, String key) throws Exception {
		Key aesKey = getSecKey(key, "AES");

		Cipher enCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		byte[] iv = new byte[16];
		IvParameterSpec ivspec = new IvParameterSpec(iv);

		enCipher.init(Cipher.DECRYPT_MODE, aesKey, ivspec);
		byte[] pasByte = enCipher.doFinal(Base64.decode(input));
		return new String(pasByte, "UTF-8");
	}

	public static String[] generateRSAKeyPair() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair kp = keyGen.generateKeyPair();
		byte[] publicKey = kp.getPublic().getEncoded();
		byte[] privateKey = kp.getPrivate().getEncoded();

		String[] strKeys = new String[2];
		strKeys[0] = Base64.encode(publicKey, true);
		strKeys[1] = Base64.encode(privateKey, true);

		return strKeys;
	}

	public static String encryptRSA(String input, String privateKey) throws Exception {
		KeyFactory kf = KeyFactory.getInstance("RSA");
		Key prikey = kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(privateKey)));

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, prikey);

		return Base64.encode(cipher.doFinal(input.getBytes("UTF-8")), true);
	}

	public static String decryptRSA(String input, String publicKey) throws Exception {
		KeyFactory kf = KeyFactory.getInstance("RSA");
		Key pubKey = kf.generatePublic(new X509EncodedKeySpec(Base64.decode(publicKey)));

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, pubKey);

		return new String(cipher.doFinal(Base64.decode(input)), "UTF-8");
	}
}
