import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import csec2013.AES;

public class Test {

	public static void main(String[] args) {
		
		byte[] test2 = new byte[4];
		System.out.println("String: " + test2[0]);
		//generate a key using Java's built-in methods
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
		keyGen.init(128); //set the size of the key (can be changed)
		SecretKey keyObj = keyGen.generateKey();
		byte[] key = keyObj.getEncoded();

		AES test = null;
		try {
			test = new AES(key);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		byte[] state = //plaintext (2 blocks)
			{(byte) 0x54, (byte)0x44, (byte)0x88, (byte)0xcc, (byte)0x11,(byte) 0x55, (byte)0x91, (byte)0xdd, 
				(byte)0x22, (byte)0x66, (byte)0xaf, (byte)0xed, (byte)0x36, (byte)0x77, (byte)0xcb, 
				(byte)0xff, (byte)0x92, (byte)0x44, (byte)0x88,(byte) 0xcc, (byte)0x11, (byte)0x55, 
				(byte)0x99, (byte)0xda, (byte)0x22,(byte) 0x66, (byte)0xaa, (byte)0xee, (byte)0x33, 
				(byte)0x00, (byte)0xbb, (byte)0xff};
		 
		 byte[] n = test.encrypt(state);
		 test.decrypt(n);

	}
	
	/*
	 * Prints a byte array in human readable form. Only used for checking.
	 * @param byte[] words the array to print
	 */
	private static void PrintArray(byte[] words) 
	{
		for (int i = 0; i < words.length; i++)
		{
				System.out.print(Integer.toHexString((words[i] & 0xFF)) + " ");
		}
	}

}
