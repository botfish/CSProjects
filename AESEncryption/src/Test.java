import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Test {

	public static void main(String[] args) {
		/*int[] key = {0x2b,0x7e,0x15,0x16,
			 	0x28,0xae,0xd2,0xa6,
			 	0xab,0xf7,0x15,0x88,
			 	0x09,0xcf,0x4f,0x3c};*/
		
		//generate a key using Java's built-in methods
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		keyGen.init(128); //set the size of the key (can be changed)
		SecretKey keyObj = keyGen.generateKey();
		byte[] key = keyObj.getEncoded();
		
		AES test = null;
		try {
			test = new AES(key);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		 int[][] state =
				{{0x32, 0x88, 0x31, 0xe0},
				 {0x43, 0x5a, 0x31, 0x37},
				 {0xf6, 0x30, 0x98, 0x07},
				 {0xa8, 0x8d, 0xa2, 0x34}};
		 
		 byte[] test1 = intToByte(state);
		 byte[] n = test.encrypt(test1);
		 test.decrypt(n);

	}
	
	public static byte[] intToByte(int[][] in) {
		byte[] result = new byte[in.length*in[0].length];
		int k = 0;
		for (int i = 0; i < in.length; i++) {
			for (int j = 0; j < in[0].length; j++) {
				result[k] = (byte)in[i][j];
				k += 1;
			}
		}
		return result;
	}

}
