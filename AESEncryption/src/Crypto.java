/*
 * This class sets up the Diffie-Hellman key exchange for the chat program and
 * provides it with the ciphers necessary for encryption and decryption.
 */

import java.awt.RenderingHints.Key;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import csec2013.CSec2013Prov;


public class Crypto {
	private AlgorithmParameters params;
	private Provider prov;
	private KeyAgreement keyAgree;
	private SecretKey aesKey; //the key for the AES encryption/decryption
	private byte[] IV = null; //param for initial vector
	private IvParameterSpec spec;
	private Cipher encrypt; //cipher for encryption
	private Cipher decrypt; //cipher for decryption
	private boolean do_cbc;
	
	/*
	 * Creates and returns the cipher for encryption.
	 * @param params the string parameters for algorithm/chaining/packing
	 * @return a Cipher
	 */
	private void buildEncrypt(String sets) {
		try {
			//create cipher
			encrypt = Cipher.getInstance(sets);
			if (sets.contains("CBC")) { 
				do_cbc = true;
				//generate initial vector if server
				if (IV == null) {
					System.out.println("Generating initial vector...");
					IV = new byte[16];
					new SecureRandom().nextBytes(IV);
					spec = new IvParameterSpec(IV);
				}
				else {
					spec = new IvParameterSpec(IV);
				}
				//add keys
				encrypt.init(Cipher.ENCRYPT_MODE, aesKey, spec);
			}
			else if (sets.contains("ECB")) {
				do_cbc = false;
				spec = null;
				encrypt.init(Cipher.ENCRYPT_MODE, aesKey, spec);
			}
			else { 
				throw new NoSuchAlgorithmException();
			}

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(0);
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} 
	}
	
	/*
	 * Creates and returns the cipher for decryption.
	 * @param params the string parameters for algorithm/chaining/packing
	 * @return a Cipher
	 */
	private void buildDecrypt(String sets) {
		try {
			//create cipher
			decrypt = Cipher.getInstance(sets);
			//add key
			if (sets.contains("CBC")) { 
				do_cbc = true;
				decrypt.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(IV));
			}
			else if (sets.contains("ECB")) {
				do_cbc = false;
				spec = null;
				decrypt.init(Cipher.DECRYPT_MODE, aesKey, spec);
			}
			else {
				throw new NoSuchAlgorithmException();
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(0);
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}
	
	/*
	 * This method runs the client's side of the exchange.
	 * @param Socket c the socket to communicate on
	 */
	public void clientKeySetup(Socket c) {
		try {
			//create the provider
    		prov = new CSec2013Prov();
    		//insert the provider at position 1 (highest priority)
    		Security.insertProviderAt(prov, 1);
    		
			InputStream in = c.getInputStream();
			OutputStream out = c.getOutputStream();
			//get encoded parameters from server
			byte[] temp = new byte[1024];
			int len = in.read(temp);
			byte[] sParams = new byte[len];
			System.arraycopy(temp, 0, sParams, 0, len);
			System.out.println("Received initial parameters...");
			params = AlgorithmParameters.getInstance("DH");
			params.init(sParams);
			System.out.println("Decoded initial parameters...");
		
			//generate DH keys
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
			KeyPair keys = keyGen.genKeyPair();
			//send public key
			System.out.println("Sending encoded public key...");
			out.write(keys.getPublic().getEncoded());
			
			//get other side's client key
			byte[] tem = new byte[1024];
			int l = in.read(tem);
			byte[] pKey = new byte[l];
			System.arraycopy(tem, 0, pKey, 0, l);
			//decode the key using KeyFactory
			System.out.println("Decoding other side's public key...");
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pKey);
			KeyFactory fact = KeyFactory.getInstance("DH");
			PublicKey pubKey = fact.generatePublic(pubKeySpec);

			//create KeyAgreement
			System.out.println("Creating KeyAgreement...");
			keyAgree = KeyAgreement.getInstance("DH");
			keyAgree.init(keys.getPrivate()); //add private key
		    keyAgree.doPhase(pubKey, true); //add other public key
		    
		    //generate shared secrets (AES key and IV)
		    System.out.println("Generating AES key...");
		    aesKey = keyAgree.generateSecret("AES");
		    
		    //generate Ciphers
		    System.out.println("Constructing ciphers...");
		    //get IV from server
		    try {
		    	IV = new byte[16];
		    	in.read(IV);
		    	if (IV[0] == ((byte)-1)) {
		    		do_cbc = false;
		    	}
		    }
		    catch (Exception e) {
		    	do_cbc = false;
		    }

		    buildEncrypt("AES/CBC/PKCS5Padding");
		    buildDecrypt("AES/CBC/PKCS5Padding");
		    
		    System.out.println("Using cipher provider: " + encrypt.getProvider());
		
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalStateException e) {
			e.printStackTrace();
		} 
		
		
	}
	
	/*
	 * This method runs the server's side of the exchange.
	 * @param Socket c the socket to communicate on
	 */
	public void serverKeySetup(Socket c) {
    	try {
    		//create the provider
    		prov = new CSec2013Prov();
    		//insert the provider at position 1 (highest priority)
    		Security.insertProviderAt(prov, 1);
    		//generate the generator
    		System.out.println("Generating initial parameters...");
    		AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DH");
    		//set the size
    		gen.init(1024);
    		//generate the parameters for Diffie-Hellman
   			params = gen.generateParameters();
    		//send the encoded parameters
    		System.out.println("Sending initial parameters...");
    		InputStream in = c.getInputStream();
   			OutputStream out = c.getOutputStream();
   			out.write(params.getEncoded());
    		//generate DH keys
    		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
    		KeyPair keys = keyGen.genKeyPair();
   			//send public key
   			System.out.println("Sending encoded public key...");
   			out.write(keys.getPublic().getEncoded());
   			
   			//get other side's client key
			byte[] tem = new byte[1024];
			int l = in.read(tem);
			byte[] pKey = new byte[l];
			System.arraycopy(tem, 0, pKey, 0, l);
   			//decode the key using KeyFactory
   			System.out.println("Decoding other side's public key...");
    		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pKey);
    		KeyFactory fact = KeyFactory.getInstance("DH");
    		PublicKey pubKey = fact.generatePublic(pubKeySpec);

   			//create KeyAgreement
    		System.out.println("Creating KeyAgreement...");
   			keyAgree = KeyAgreement.getInstance("DH");
   			keyAgree.init(keys.getPrivate()); //add private key
   		    keyAgree.doPhase(pubKey, true); //add other public key
   		    
   		    //generate shared secrets (AES key and IV)
		    System.out.println("Generating AES key...");
		    aesKey = keyAgree.generateSecret("AES");
		    
		    //generate Ciphers
		    System.out.println("Constructing ciphers...");
		    buildEncrypt("AES/CBC/PKCS5Padding");
		    buildDecrypt("AES/CBC/PKCS5Padding");

		    //send IV to client
		    if (do_cbc) {
		    	out.write(IV);
		    }
		    else {
		    	out.write((byte)-1);
		    }
		    
		    System.out.println("Using cipher provider: " + encrypt.getProvider());
   			
    	} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalStateException e) {
			e.printStackTrace();
		}
    }
	
	/*
	 * @return the encryption Cipher
	 */
	public Cipher encryptCipher() {
		return encrypt;
	}
	
	/*
	 * @return the decryption Cipher
	 */
	public Cipher decryptCipher() {
		return decrypt;
	}
	
	/*
	 * @return the shared AES key
	 */
	public SecretKey getKey() {
		return aesKey;
	}
	
	/*
	 * @return the initial vector for block chaining
	 */
	public byte[] getIV() {
		return IV;
	}

}
