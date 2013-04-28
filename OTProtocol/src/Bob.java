import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.*;

/*
 * This class implements Bob's side of the Oblivious Transfer Protocol.
 */

public class Bob {
    private TLVInputStream in;
    private TLVOutputStream out;
    private SecureRandom random = new SecureRandom();
    private String Msg = "I lose. ~Alice:("; //length must be a multiple of 16
    private String test = "OneTwoThreeFour1";
    //Does Bob get to know the message?

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
        int result = -10; // Some result code not used anywhere else

        try {
            Socket clientSocket = new Socket("localhost", 8023);
            
            Bob sideB = new Bob(clientSocket.getInputStream(), clientSocket.getOutputStream());
            result = sideB.execute();
            
        } catch (UnknownHostException e) {
            System.err.println("Don't know about host");
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to host");
        } catch (OTPException e) {
            System.err.println("\nError executing OTP: " + e);
			e.printStackTrace();
		}
        
        switch (result) {
        case Outcome.LOSE: {
            System.out.println("I Lose");
        } break;
        case Outcome.WIN: {
            System.out.println("I Win");
        } break;
        default: {
            // This should never happen
            System.err.println("Internal Error");
        }
    }
    System.exit(result);


	}

	/**
     * Execute side B of the Oblivious Transfer Protocol.
     *
     * Executes the OTP using the provided communication channels.
     * @return the outcome of the OTP: Outcome.WIN or Outcome.LOSE.
     */
    public int execute() throws OTPException {
    	//Part 1
    	System.err.println(1); //only Alice does this
    	
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
        	//don't use the Common function, it could be rigged?
			//KeySend = Common.encryptKey((RSAPublicKey) publicKey, AesKey, r);		// Encrypting the AES with with the Randomly chosen Public Key
        	Cipher c = Cipher.getInstance("RSA/ECB/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] K_data = AesKey.getEncoded();
            int block_len = (((RSAPublicKey)publicKey).getModulus().bitLength() + 7) / 8;
            ByteBuffer data = ByteBuffer.allocate(2 + block_len);
            data.putShort((short)K_data.length);
            data.put(c.doFinal(K_data));
            KeySend = data.array();
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
        byte[] message = null;
        byte[] K_G = null;
        try {
        	message = in.get(0x60);
        	//receive number of key used
        	K_G = in.get(0x61);
        } catch (IOException e) {
            throw new OTPException("Unable to receive encrypted key", e);
        }
        
        if(K_G.length > 1)
        {
        	throw new OTPException("Alice Sent to long of a coin flip result");
        }
        
        byte K_G_result = K_G[0];

        
        byte[] decrypted = null;
        byte[] K_I_Priv = null;
        byte[] K_J_Priv = null;
        try {
        	//Step 7 of the OTP
        	System.err.println(7);
        	//build Cipher for decryption
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, AesKey);
            //attempt to decrypt message using Kb
			decrypted = cipher.doFinal(message);
			
			//CHEATING BOB!
			//out.put(0x70, Msg.getBytes());
			//out.putByte(0x71, K_G_result);
			
			//Benign Bob
			//send message back to Alice
			out.put(0x70, decrypted);
			//send key choice to Alice
			out.putByte(0x71, H);

			//Step 8 of the OTP
			System.err.println(8);
	    	//get private keys from Alice
			K_I_Priv = in.get(0x80);
			K_J_Priv = in.get(0x81);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    	
        //verify keys
        if (K_I_Pub == K_J_Pub)		// Cheating
        {
        	throw new OTPCheatException("Alice sent the same public key twice.");
        }
        else if (K_I_Priv == K_J_Priv) {
        	throw new OTPCheatException("Alice sent the same private key twice.");
        }
        
        //test to make sure the public keys match the private ones by testing them
        try {
        	//Test the K_I keys
        	PublicKey KI_Public = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(K_I_Pub));
        	Cipher encrypt = Cipher.getInstance("RSA");
        	encrypt.init(Cipher.ENCRYPT_MODE, KI_Public);
        	byte[] temp = encrypt.doFinal(test.getBytes()); //encrypted test string
        	
        	PrivateKey KI_Private = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(K_I_Priv));
        	Cipher decrypt = Cipher.getInstance("RSA");
        	decrypt.init(Cipher.DECRYPT_MODE, KI_Private);
        	String temp2 = new String(decrypt.doFinal(temp), "UTF-8");
        	
        	if (!temp2.equals(test)) {
        		throw new OTPCheatException("The private key Alice sent for K_I does not decrypt messages encrypted by " +
        				"the K_I public key.");
        	}
        	
        	//Test the K_J keys using the same method
        	PublicKey KJ_Public = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(K_J_Pub));
        	encrypt = Cipher.getInstance("RSA");
        	encrypt.init(Cipher.ENCRYPT_MODE, KJ_Public);
        	temp = encrypt.doFinal(test.getBytes()); //encrypted test string
        	
        	PrivateKey KJ_Private = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(K_J_Priv));
        	decrypt = Cipher.getInstance("RSA");
        	decrypt.init(Cipher.DECRYPT_MODE, KJ_Private);
        	temp2 = new String(decrypt.doFinal(temp), "UTF-8");
        	
        	if (!temp2.equals(test)) {
        		throw new OTPCheatException("The private key Alice sent for K_J does not decrypt messages encrypted by " +
        				"the K_J public key.");
        	}
        	
        	
        } catch (InvalidKeySpecException e) {
        	e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        String M = new String(decrypted);
        if (M.equals(Msg)) {
        	if (H == K_G_result) {
        		return Outcome.WIN;
        	}
        }
        else if (H == K_G_result && !M.equals(Msg))
        {
    		throw new OTPCheatException("Keys were guessed correctly, but the standard message was not succesffully decrypted.");
        	
        }
        else if (H != K_G_result && !M.equals(Msg))
        {
        	return Outcome.LOSE;
        }
    	else {
    		//if the message and keys do not match, you lose
    		throw new OTPException("Something went wrong.");
    	}
        
        return -1;

		

    }

}