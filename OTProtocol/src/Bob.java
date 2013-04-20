import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.*;

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
    	
    	//*********************************//
    	//**generate AES symmetric key Kb**//
    	//*********************************//
    	SecretKey AesKey = null;
    	
    	System.err.println(2);
    	
        try {
        	KeyGenerator Gen = KeyGenerator.getInstance("AES");	
        	Gen.init(128);
        	AesKey = Gen.generateKey();				// Generate a Random Key for AES
        }catch (NoSuchAlgorithmException e)
        {
        	throw new OTPException("No Such Algorithm -AES");
        }

    	
    	System.out.println("Generated Key");
    	
    	//**************************************//
    	//**receive two public keys from Alice**//
    	//**************************************//
        System.err.println(3);
        
        byte[] K_I_Pub = null;
        try {
        	K_I_Pub = in.get(0x30);
        } catch (IOException e) {
            throw new OTPException("Unable to receive encrypted key", e);
        }
        
        System.out.println("Key 2");
        
        byte[] K_J_Pub = null;
        try {
        	K_J_Pub = in.get(0x31);
        } catch (IOException e) {
            throw new OTPException("Unable to receive encrypted key", e);
        }
            
        //*********************************//
    	//**randomly pick one of the keys**//
        //*********************************//
        
        System.err.println(4);
        byte H = (byte)(new BigInteger(1, random).intValue());
        byte [] K_H = H == 0 ? K_I_Pub : K_J_Pub;
        

        //*******************************//
    	//****encrypt symmetric key*****//
        //******************************//
        
        SecureRandom r = new SecureRandom();
        byte[] KeySend = null;
        PublicKey publicKey = null;
		try {
			publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(K_H));		// Turning the byte array back into RSA Public Key.
		} catch (InvalidKeySpecException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
        
        try {
			KeySend = Common.encryptKey((RSAPublicKey) publicKey, AesKey, r);		// Encrypting the AES with with the Randomly chosen Public Key
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

        
        
        
        //*******************************//
    	//**send encrypted key to Alice**//
        //*******************************//
        
        try {
            out.put(0x40, KeySend);
        } catch (IOException e) {
            throw new OTPException("Unable to send public key to Alice", e);
        }
    	
///////////////////////////////////////////////////////////////////////////////////////////////    	
        
 
    	//Part 2
        //****************************************//
    	//**receive encrypted message from Alice**//
        //****************************************//
        System.err.println(6);
        byte[] Message = null;
        try {
        	Message = in.get(0x60);
        } catch (IOException e) {
            throw new OTPException("Unable to receive encrypted key", e);
        }
        
        
    	//attempt to decrypt message
    	//send message back to Alice
    	//get private keys from Alice
        //verify keys
    	//return some int
    	
    	
        
        
        if(K_I_Pub == K_J_Pub)		// Cheating
        {
        	throw new OTPCheatException("Alice sent the same Public key twice");
        }
        else
        {
        return Outcome.LOSE;	// simple return just for testing.
        }
    }

}
