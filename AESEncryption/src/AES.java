import java.nio.ByteBuffer;


public class AES {
	
	final private static int Nb = 4;
	
	//the table for the S-boxes. NOTE: Indices greater than 9 will need to be converted from hex to integer
	final private static int[][] subTable = 
			{{0x63,0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
			 {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
			 {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
			 {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
			 {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
			 {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
			 {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
			 {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
			 {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
			 {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
			 {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
			 {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
			 {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
			 {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
			 {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
			 {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};
	//the table for the Inverse S-boxes
	final private static int[][] invSubTable = 
		{{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
	     {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
	     {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
	     {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
	     {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
	     {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
	     {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
	     {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
	     {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
	     {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
	     {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
	     {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
	     {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
	     {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
	     {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
	     {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};
	
	      //Tables for byte multiplication

			// the "E" table -- antilogs
			 private final static int[][] Etable = 
			{{0x01, 0x03, 0x05, 0x0F, 0x11, 0x33, 0x55, 0xFF, 0x1A, 0x2E, 0x72, 0x96, 0xA1, 0xF8, 0x13, 0x35},
			 {0x5F, 0xE1, 0x38, 0x48, 0xD8, 0x73, 0x95, 0xA4, 0xF7, 0x02, 0x06, 0x0A, 0x1E, 0x22, 0x66, 0xAA},
			 {0xE5, 0x34, 0x5C, 0xE4, 0x37, 0x59, 0xEB, 0x26, 0x6A, 0xBE, 0xD9, 0x70, 0x90, 0xAB, 0xE6, 0x31},
			 {0x53, 0xF5, 0x04, 0x0C, 0x14, 0x3C, 0x44, 0xCC, 0x4F, 0xD1, 0x68, 0xB8, 0xD3, 0x6E, 0xB2, 0xCD},
			 {0x4C, 0xD4, 0x67, 0xA9, 0xE0, 0x3B, 0x4D, 0xD7, 0x62, 0xA6, 0xF1, 0x08, 0x18, 0x28, 0x78, 0x88},
			 {0x83, 0x9E, 0xB9, 0xD0, 0x6B, 0xBD, 0xDC, 0x7F, 0x81, 0x98, 0xB3, 0xCE, 0x49, 0xDB, 0x76, 0x9A},
			 {0xB5, 0xC4, 0x57, 0xF9, 0x10, 0x30, 0x50, 0xF0, 0x0B, 0x1D, 0x27, 0x69, 0xBB, 0xD6, 0x61, 0xA3},
			 {0xFE, 0x19, 0x2B, 0x7D, 0x87, 0x92, 0xAD, 0xEC, 0x2F, 0x71, 0x93, 0xAE, 0xE9, 0x20, 0x60, 0xA0},
			 {0xFB, 0x16, 0x3A, 0x4E, 0xD2, 0x6D, 0xB7, 0xC2, 0x5D, 0xE7, 0x32, 0x56, 0xFA, 0x15, 0x3F, 0x41},
			 {0xC3, 0x5E, 0xE2, 0x3D, 0x47, 0xC9, 0x40, 0xC0, 0x5B, 0xED, 0x2C, 0x74, 0x9C, 0xBF, 0xDA, 0x75},
			 {0x9F, 0xBA, 0xD5, 0x64, 0xAC, 0xEF, 0x2A, 0x7E, 0x82, 0x9D, 0xBC, 0xDF, 0x7A, 0x8E, 0x89, 0x80},
			 {0x9B, 0xB6, 0xC1, 0x58, 0xE8, 0x23, 0x65, 0xAF, 0xEA, 0x25, 0x6F, 0xB1, 0xC8, 0x43, 0xC5, 0x54},
			 {0xFC, 0x1F, 0x21, 0x63, 0xA5, 0xF4, 0x07, 0x09, 0x1B, 0x2D, 0x77, 0x99, 0xB0, 0xCB, 0x46, 0xCA},
			 {0x45, 0xCF, 0x4A, 0xDE, 0x79, 0x8B, 0x86, 0x91, 0xA8, 0xE3, 0x3E, 0x42, 0xC6, 0x51, 0xF3, 0x0E},
			 {0x12, 0x36, 0x5A, 0xEE, 0x29, 0x7B, 0x8D, 0x8C, 0x8F, 0x8A, 0x85, 0x94, 0xA7, 0xF2, 0x0D, 0x17},
			 {0x39, 0x4B, 0xDD, 0x7C, 0x84, 0x97, 0xA2, 0xFD, 0x1C, 0x24, 0x6C, 0xB4, 0xC7, 0x52, 0xF6, 0x01}};
			
			//the "L" table -- logs
			private final static int[][] Ltable=
			{{0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1A, 0xC6, 0x4B, 0xC7, 0x1B, 0x68, 0x33, 0xEE, 0xDF, 0x03},
			 {0x64, 0x04, 0xE0, 0x0E, 0x34, 0x8D, 0x81, 0xEF, 0x4C, 0x71, 0x08, 0xC8, 0xF8, 0x69, 0x1C, 0xC1},
			 {0x7D, 0xC2, 0x1D, 0xB5, 0xF9, 0xB9, 0x27, 0x6A, 0x4D, 0xE4, 0xA6, 0x72, 0x9A, 0xC9, 0x09, 0x78},
			 {0x65, 0x2F, 0x8A, 0x05, 0x21, 0x0F, 0xE1, 0x24, 0x12, 0xF0, 0x82, 0x45, 0x35, 0x93, 0xDA, 0x8E},
			 {0x96, 0x8F, 0xDB, 0xBD, 0x36, 0xD0, 0xCE, 0x94, 0x13, 0x5C, 0xD2, 0xF1, 0x40, 0x46, 0x83, 0x38},
			 {0x66, 0xDD, 0xFD, 0x30, 0xBF, 0x06, 0x8B, 0x62, 0xB3, 0x25, 0xE2, 0x98, 0x22, 0x88, 0x91, 0x10},
			 {0x7E, 0x6E, 0x48, 0xC3, 0xA3, 0xB6, 0x1E, 0x42, 0x3A, 0x6B, 0x28, 0x54, 0xFA, 0x85, 0x3D, 0xBA},
			 {0x2B, 0x79, 0x0A, 0x15, 0x9B, 0x9F, 0x5E, 0xCA, 0x4E, 0xD4, 0xAC, 0xE5, 0xF3, 0x73, 0xA7, 0x57},
			 {0xAF, 0x58, 0xA8, 0x50, 0xF4, 0xEA, 0xD6, 0x74, 0x4F, 0xAE, 0xE9, 0xD5, 0xE7, 0xE6, 0xAD, 0xE8},
			 {0x2C, 0xD7, 0x75, 0x7A, 0xEB, 0x16, 0x0B, 0xF5, 0x59, 0xCB, 0x5F, 0xB0, 0x9C, 0xA9, 0x51, 0xA0},
			 {0x7F, 0x0C, 0xF6, 0x6F, 0x17, 0xC4, 0x49, 0xEC, 0xD8, 0x43, 0x1F, 0x2D, 0xA4, 0x76, 0x7B, 0xB7},
			 {0xCC, 0xBB, 0x3E, 0x5A, 0xFB, 0x60, 0xB1, 0x86, 0x3B, 0x52, 0xA1, 0x6C, 0xAA, 0x55, 0x29, 0x9D},
			 {0x97, 0xB2, 0x87, 0x90, 0x61, 0xBE, 0xDC, 0xFC, 0xBC, 0x95, 0xCF, 0xCD, 0x37, 0x3F, 0x5B, 0xD1},
			 {0x53, 0x39, 0x84, 0x3C, 0x41, 0xA2, 0x6D, 0x47, 0x14, 0x2A, 0x9E, 0x5D, 0x56, 0xF2, 0xD3, 0xAB},
			 {0x44, 0x11, 0x92, 0xD9, 0x23, 0x20, 0x2E, 0x89, 0xB4, 0x7C, 0xB8, 0x26, 0x77, 0x99, 0xE3, 0xA5},
			 {0x67, 0x4A, 0xED, 0xDE, 0xC5, 0x31, 0xFE, 0x18, 0x0D, 0x63, 0x8C, 0x80, 0xC0, 0xF7, 0x70, 0x07}};
  	
	/**
	 * Constructor function
	 * @param key Hex string of the key
	 */
	public AES(String key) {
		
		
	}
	
	/**
	 * This is just being left here for debugging functions. It won't be needed in the final class.
	 */
	public static void main(String[] args) {
		System.out.println(Integer.toHexString(byteMultiplyX(0x57,0x13)));
	}
	
	/*
	 * Multiplies 2 word values (it is assumed there are 4 bytes in a word)
	 * @param int num1
	 * @param int num2
	 * @return the multiplication result
	 */
	private static int wordMultiply(int num1, int num2) {
		int[] a = intToArray(num1);
		int[] b = intToArray(num2);
		int[] d = new int[4];
		d[0] = addition(addition(addition(byteMultiply(a[0],b[0]), byteMultiply(a[3],b[1])),byteMultiply(a[2],b[2])), byteMultiply(a[1],b[3]));
		d[1] = addition(addition(addition(byteMultiply(a[1],b[0]), byteMultiply(a[0],b[1])),byteMultiply(a[3],b[2])), byteMultiply(a[2],b[3]));
		d[2] = addition(addition(addition(byteMultiply(a[2],b[0]), byteMultiply(a[1],b[1])),byteMultiply(a[0],b[2])), byteMultiply(a[3],b[3]));
		d[3] = addition(addition(addition(byteMultiply(a[3],b[0]), byteMultiply(a[2],b[1])),byteMultiply(a[1],b[2])), byteMultiply(a[0],b[3]));
		return d[0];
	}
	
	/*
	 * Converts an int word to an array of integer bytes.
	 * @param int num
	 * @return int array
	 */
	private static int[] intToArray(int num) {
		byte[] a1 = ByteBuffer.allocate(4).putInt(num).array();
		int[] a = new int[4];
		for (int i = 0; i < 4; i++) {
			a[i] = (int)a1[i];
		}
		return a;
	}
	
	/*
	 * More efficient version of byte multiplication.
	 * @param int num1
	 * @param int num2
	 * @return the multiplication result
	 */
	private static int byteMultiplyX(int num1, int num2) {
		 int result;
		 int r1 = xtime(num1);
		 if ((num2 % 2) == 1) {
			 result = num1;
		 }
		 else {
			 result = 0x0;
		 }
		 num2>>>=1;
		 while (num2 != 0) {
			 if ((num2 % 2) == 1) {
				 result = addition(result, r1);
			 }
			 num2>>>=1;
			 r1 = xtime(r1);
		 }
		 return result;
	}
	
	/*
	 * Multiply by X, depending on first bit
	 * @param int num
	 * @return the result
	 */
	private static int xtime(int num) {
		int temp = num;   
        temp &= 0x80; 
        num <<= 1;  //multiply by 2
        if (temp == 0x80) //if the first bit is 1
        {   
                num ^= (0x1b);   
        }   
        return num & 0xff; //only the last two digits   
	}
	
	/*
	 * Multiply two numbers by adding logs and get the result from the antilog.
	 * @param int num1
	 * @param int num2
	 * @return the result of the multiplication of num1 and num2
	 */
	private static int byteMultiply(int num1, int num2) {
		int total = GetRowCol(num1) + GetRowCol(num2);
		if (total > 255) {
			total=total-255 ; 	// make sure the total isn't bigger than 255
		}
		
		//get the result from the antilog table
		int row = total>>>4;
		int col = total<<28;
		col = col>>>28;
		return Etable[row][col];
		
	}
	
	/*
	 * Uses the hex values to index a table of log values for byte multiplication
	 */	
	private static int GetRowCol(int num1)
	{
		int row = num1 ;
		int col = num1 ;
		
		row>>>=4;
		col<<=28;
		col>>>=28;
		return Ltable[row][col];
	}
	
	
	/*
	 * This function adds two binary strings using bitwise XORs. It assumes that both
	 * numbers are have the same length. This should be usable for both byte and word addition.
	 * @param num1 Hex string of the first number
	 * @param num2 Hex string of the second number 
	 * @return the added string
	 */
	private static String addition(String num1, String num2) {
		//It's easier just to convert the strings to integers and XOR them, 
		//rather than doing it character by character.
		int n1 = Integer.parseInt(num1.replace("0x", ""), 16);
		int n2 = Integer.parseInt(num2.replace("0x", ""), 16);
		int result = (n1 ^ n2); //actual XOR
		return Integer.toHexString(result);
	}
	
	/*
	 * Integer version of above function.
	 */
	private static int addition(int num1, int num2) {
		//It's easier just to convert the strings to integers and XOR them, 
		//rather than doing it character by character.
		int result = (num1 ^ num2); //actual XOR
		return result;
	}
	
	private static void SubBytes(int[][] state)
	{
		for(int row=0; row<4; row++)
		{
			for(int col=0; col<Nb; col++)
			{
				int x; int y;
				 x=left(state[row][col]);
				 y=right(state[row][col]);	
				 state[row][col]=subTable[x][y];
			}
		}
		
			
	}
	
	private static void invSubBytes(int[][] state)
	{
		for(int row=0; row<4; row++){
			for(int col=0; col<Nb; col++){
				int x; int y;
				 x=left(state[row][col]);
				 y=right(state[row][col]);	
				 state[row][col] = invSubTable[x][y];
			}
		}
	}
	
	private static int left( int val )
	   {
	        final int LMASK=0x000000f0;
	        return (  (val & LMASK)>>4 );
	   }
	 
	private static int right( int val )
	   {
	        final int RMASK=0x0000000f;
	        return (  (val & RMASK) );
	        
	   }
	
	/*
	private static int byteMultiply(int num1, int num2) 
	{
		int total = Ltable[left(num1)][right(num1)] + Ltable[left(num2)][right(num2)];
		if (total > 255) {
			total=total-255 ; 	// make sure the total isn't bigger than 255
			}
			
			//get the result from the antilog table
			
			return Etable[left(total)][right(total)];
	}*/
	
	public static void shiftRows(int[][] state)
	{
		int[] temp= new int[4];
		for (int row=0; row<4; row++)
		{
			for(int col=0; col<Nb; col++)
			{
				// need to shift each row over 'row' times
				// i.e., row 0 does not shift, row 1 shifts elements to the left by 1,
				// row 2 shifts elements to the left by 2, etc
				// (col + row) mod Nb will give us what we want
				
				// store values into a temp array
				temp[col]=state[row][(col+row)%Nb];
			for(col=0; col<Nb; col++)
			{
				// write values into state
				state[row][col] = temp [col];
			}
			}
		}
	}
	
	public static void InvShiftRows(int[][] state)
	{
		int[] temp= new int[4];
		for (int row=0; row<4; row++)
		{
			for(int col=0; col<Nb; col++)
			{
				// For the Inverse
				// need to shift RIGHT each row over 'row' times
				// i.e., row 0 does not shift, row 1 shifts elements to the right by 1,
				// row 2 shifts elements to the right by 2, etc
				// (col + row) mod Nb will give us what we want
				
				// store values into a temp array
				temp[(col+row)%Nb]=state[row][col];
			for(col=0; col<Nb; col++)
			{
				// write values into state
				state[row][col] = temp [col];
			}
			}
		}
	}
	public static void MixCols(int [][] state)
	{
		int[] temp= new int[4];
		for (int col=0; col<Nb; col++)
		{
			// compute new columns, store in temp vector, write to new state afterwards
			temp[0] = byteMultiply(state[0][col],2) ^ byteMultiply(state[1][col],3) ^
						state[2][col] ^ state[3][col];
			temp[1] = state[0][col] ^ byteMultiply(state[1][col],2) ^
						byteMultiply(state[2][col],3) ^ state[3][col];
			temp[2] = state[0][col] ^ state[1][col] ^ 
						byteMultiply(state[2][col],2) ^ byteMultiply(state[3][col],3);
			temp[3] = byteMultiply(state[0][col],3) ^ state[1][col] ^
						state[2][col] ^ byteMultiply(state[3][col],2);
			
			for (int i=0; i<4; i++)
			{
				state[i][col] = temp[i];
			}      
		}
	}
	
	public static void InvMixCols(int [][] state)
	{
		int[] temp= new int[4];
		for (int col=0; col<Nb; col++)
		{
			// compute new columns, store in temp vector, write to new state afterwards
			temp[0] = byteMultiply(state[0][col],0x0e) ^ byteMultiply(state[1][col],0x0b)
				   ^  byteMultiply(state[2][col],0x0d) ^ byteMultiply(state[3][col],0x09);
			temp[1] = byteMultiply(state[0][col],0x09) ^ byteMultiply(state[1][col],0x0e)
				   ^  byteMultiply(state[2][col],0x0b) ^ byteMultiply(state[3][col],0x0d);
			temp[2] = byteMultiply(state[0][col],0x0d) ^ byteMultiply(state[1][col],0x09) 
				   ^  byteMultiply(state[2][col],0x0e) ^ byteMultiply(state[3][col],0x0b);
			temp[3] = byteMultiply(state[0][col],0x0b) ^ byteMultiply(state[1][col],0x0d)
				   ^  byteMultiply(state[2][col],0x09) ^ byteMultiply(state[3][col],0x0e);
			
			for (int i=0; i<4; i++)
			{
				state[i][col] = temp[i];
			}      
		}
	}
	
	

}
