import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Test {

	public static void main(String[] args) {
		/*int[] key = {0x2b,0x7e,0x15,0x16,
			 	0x28,0xae,0xd2,0xa6,
			 	0xab,0xf7,0x15,0x88,
			 	0x09,0xcf,0x4f,0x3c}; 128-bit */
		
		//generate a key using Java's built-in methods
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
		keyGen.init(256); //set the size of the key (can be changed)
		SecretKey keyObj = keyGen.generateKey();
		byte[] key = keyObj.getEncoded();

		AES test = null;
		try {
			test = new AES(key);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		int[][] state =
			{{0x00, 0x44, 0x88, 0xcc},
			 {0x11, 0x55, 0x99, 0xdd},
			 {0x22, 0x66, 0xaa, 0xee},
			 {0x33, 0x77, 0xbb, 0xff}, {0x00, 0x44, 0x88, 0xcc},
			 {0x11, 0x55, 0x99, 0xdd},
			 {0x22, 0x66, 0xaa, 0xee},
			 {0x33, 0x77, 0xbb, 0xff}};
		 
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
