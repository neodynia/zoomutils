import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class AESUtil {
	public static void main(String[] args) throws Exception {

		String apiSecret = "abcdaj333j4j4jkl4k444";
		String apiKey = "jjhkaejdedjedljlkjd";
		String userId = "4777";
		String patientId = "338";
		String sessionId = "Z1904";
		byte[] key = getkey(apiSecret);

		String data = "usertype=1&userid="+ userId +"&sessionid=" + sessionId;

		String encryptData = aesEncrypt(data, key);
		String decrypData = aesDecrypt(encryptData, key);

		System.out.println(encryptData);
		System.out.println(decrypData);

		System.out.println(
				"https://zoom.us/telehealth?org_id=" + apiKey + "&data=" + encryptData.replaceAll("\\+", "%2B"));

	}

	public static String aesEncrypt(String str, byte[] key) throws Exception{
		if (str == null || key == null)
			return null;
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			IvParameterSpec iv = new IvParameterSpec(new byte[16]);
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), iv);
			byte[] bytes = cipher.doFinal(str.getBytes("utf-8"));
			return Base64.encodeBase64String(bytes);
		} catch (Exception e) {
			throw new Exception("AES decrypt failure");
		}
	}

	public static String aesDecrypt(String str, byte[] key) throws Exception {
		if (str == null || key == null)
			return null;
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			IvParameterSpec iv = new IvParameterSpec(new byte[16]);
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), iv);
			byte[] bytes = Base64.decodeBase64(str);
			bytes = cipher.doFinal(bytes);
			return new String(bytes, "utf-8");
		} catch (Exception e) {
			throw new Exception("AES decrypt failure");
		}
	}

	public static byte[] getkey(String key) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		digest.update(key.getBytes("utf-8"));
		byte baseData[] = digest.digest();

		byte[] buffer1 = new byte[64];
		byte[] buffer2 = new byte[64];

		for (int i = 0; i < 64; i++) {
			buffer1[i] = 0x36;
			buffer2[i] = 0x5C;
			if (i < baseData.length) {
				buffer1[i] ^= baseData[i];
				buffer2[i] ^= baseData[i];
			}
		}
		digest.update(buffer1);
		byte[] buffer1Hash = digest.digest();
		digest.update(buffer2);
		byte[] buffer2Hash = digest.digest();
		byte[] both = Arrays.copyOfRange((byte[]) ArrayUtils.addAll(buffer1Hash, buffer2Hash), 0, 16);

		return both;

	}
}
