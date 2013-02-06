
public class SubBytes {
private static int SubBytes(int[][] state)
{
	for(int row=0; row<4; row++) {
		for(int col=0; col<Nb; col++) {
			// Get value from state
			int y = state[row][col];
			int x = state[row][col];
			// parse out left and right sides
			x>>>=4;		// row of s-box
			y<<=28;
			y>>>=28;	// col of s-box
			state[row][col] = subTable[x][y];
		}
	}
}

private static int shiftRows(int[][] state)
{
	for (int row=0; row<4; row++)
		for(int col=0; col<Nb; col++)
			
			// need to shift each row over 'row' times
			// i.e., row 0 does not shift, row 1 shifts elements to the left by 1,
			// row 2 shifts elements to the left by 2, etc
			// (col + row) mod Nb will give us what we want
			
			// store values into a temp array
			temp[col]=state[row][(col+row)%Nb];
		for(col=0; col<Nb; col++)
			// write values into state
			state[row][col] = temp [col];
}
}