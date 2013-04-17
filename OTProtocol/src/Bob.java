import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;

/*
 * This class implements Bob's side of the Oblivious Transfer Protocol.
 */

public class Bob {
    private TLVInputStream in;
    private TLVOutputStream out;
    private SecureRandom random = new SecureRandom();
    private String Msg = "I lose. ~Alice:("; //length must be a multiple of 16
	
	/**
     * Default constructor.
     *
     * @param in an InputStream used to receive messages from Alice.
     * @param out an OutpuStream used to send messages to Alice.
     */
    public Bob(InputStream in, OutputStream out) {
        this.in = new TLVInputStream(in);
        this.out = new TLVOutputStream(out);
    }

	public static void main(String[] args) {
		Security.addProvider(new csec2012.CSec2012Prov());
		//connect to Alice on port 8023
		//begin protocol
	}
	
	/**
     * Execute side B of the Oblivious Transfer Protocol.
     *
     * Executes the OTP using the provided communication channels.
     * @return the outcome of the OTP: Outcome.WIN or Outcome.LOSE.
     */
    public int execute() throws OTPException {
    	//Part 1
    	//generate AES symmetric key Kb
    	//receive two public keys from Alice
    	//randomly pick one of the keys
    	//encrypt symmetric key
    	//send encrypted key to Alice
    	
    	//Part 2
    	//receive encrypted message from Alice
    	//attempt to decrypt message
    	//send message back to Alice
    	//get private keys from Alice
        //verify keys
    	//return some int
    }

}