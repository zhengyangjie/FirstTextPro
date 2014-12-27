

import java.lang.reflect.Method;

/**
 * Created by jsand on 8/14/14.
 */
public class Base64 {
	public static byte[] decode(String data) throws Exception {
		Class cls = Class.forName("sun.misc.BASE64Decoder");
		Object b64Obj = cls.newInstance();
		Method method = cls.getMethod("decodeBuffer", String.class);
		byte[] abc = (byte[])method.invoke(b64Obj, data);
		return abc;
	}

	public static String encode(byte[] data, boolean singleLine) throws Exception {
		Class cls = Class.forName("sun.misc.BASE64Encoder");
		Object b64Obj = cls.newInstance();
		Method method = cls.getMethod("encode", byte[].class);
		String str = (String)method.invoke(b64Obj, data);
		if (singleLine) {
			str = str.replaceAll("[\r\n]", "");
		}
		return str;
	}
}
