
package csec2013;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class AESCipher extends CipherSpi {
    private byte[] iv = new byte[16]; //initial vector
    private byte[] prev = new byte[16]; //ciphertext of previous block
    private boolean do_pad;
    private boolean do_cbc;
    private byte[] buffer = new byte[32]; //buffer for storing what is read in
    private int bufferOffset = 0;
    private int MODE; //mode of the cipher
    private AES aes; //actual cipher
    private byte[] resultText; //where the result is stored
    

    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
    	if (mode.equals("CBC")) {
    		do_cbc = true;
    	} else if (mode.equals("ECB")) {
    		do_cbc = false;
    	} else {
    		throw new NoSuchAlgorithmException();
    	}
    }
    
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
    	if (padding.equals("NoPadding")) {
    		do_pad = false;
    	} else if (padding.equals("PKCS5Padding")) {
    		do_pad = true;
    	} else {
    		throw new NoSuchPaddingException();
    	}
    }
    
    protected int engineGetBlockSize() {
    	return 16; // This is constant for AES.
    }
    
    protected int engineGetOutputSize(int inputLen) {
    	/**
    	 * Implement me.
    	 */
    	//find padding length
    	int pad = engineGetBlockSize() - ((inputLen + bufferOffset) % engineGetBlockSize());
    	return inputLen + bufferOffset + pad;
    	
    }
    
    protected byte[] engineGetIV() {
    	byte[] retiv = new byte[16];
    	System.arraycopy(iv, 0, retiv, 0, 16);
    	return retiv;
    }
    
    protected AlgorithmParameters engineGetParameters() {
    	AlgorithmParameters ap = null;
    	try {
    		ap = AlgorithmParameters.getInstance("AES");
    		ap.init(new IvParameterSpec(engineGetIV()));
    	} catch (NoSuchAlgorithmException e) {
    		System.err.println("Internal Error: " + e);
    	} catch (InvalidParameterSpecException e) {
    		System.err.println("Internal Error: " + e);
    	}
		return ap;
    }
    
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
    	try {
    		engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
    	} catch (InvalidAlgorithmParameterException e) {
    		System.err.println("Internal Error: " + e);
    	}
    }
    
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
      throws InvalidKeyException {
    	try {
    		engineInit(opmode, key, params.getParameterSpec(IvParameterSpec.class), random);
    	} catch (InvalidParameterSpecException e) {
    		System.err.println("Internal Error: " + e);
    	} catch (InvalidAlgorithmParameterException e) {
    		System.err.println("Internal Error: " + e);
    	}
    }
    
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    	/**
    	 * Implement me.
    	 */
    	//reset all class variables
    	bufferOffset = 0;
    	iv = new byte[16];
    	prev = new byte[16];
    	buffer = new byte[32];
    	aes = null;
    	//set the mode
    	MODE = opmode;
    	//create the cipher
    	try {
			aes = new AES(key.getEncoded());
		} catch (Exception e) {
			e.printStackTrace();
		}
    	if (do_cbc) { //if we are doing block chaining, get the IV
    		if (params == null && MODE == Cipher.DECRYPT_MODE) { //must have an IV for decryption
    			throw new InvalidKeyException();
    		}
    		else if (params == null && MODE == Cipher.ENCRYPT_MODE) {
    			//then generate IV from randomness
    			random.nextBytes(iv);   			
    		}
    		else { //get IV from params
    			if (!(params instanceof IvParameterSpec)) {
    				throw new InvalidAlgorithmParameterException();
    			}
    			iv = ((IvParameterSpec)params).getIV();
    		}
    		
    	}
    	else { //not CBC
    		if (params != null) {
    			throw new InvalidAlgorithmParameterException();
    		}
    		
    	}
    	//if the key is not the right length, reject it
    	if (key.getEncoded().length != 128 && key.getEncoded().length != 192 && key.getEncoded().length != 256) {
    		throw new InvalidKeyException();
    	}
    	
    }
    
    private int allocateSize(int inputLen) {
    	/**
    	 * Implement me.
    	 */
    	//assuming padding is not added yet
    	return inputLen + bufferOffset;
    }
    
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
    	byte[] output = new byte[allocateSize(inputLen)];
    	int size = 0;
    	try {
    		size = engineUpdate(input, inputOffset, inputLen, output, 0);
    	} catch (ShortBufferException e) {
    		System.err.println("Internal Error: " + e);
    	}
    	return Arrays.copyOf(output, size);
    }
    
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException {
    	/**
    	 * Implement me.
    	 */
    	int blockSize = engineGetBlockSize();
    	if (inputLen == 0) { //nothing to do here
    		return 0;
    	}
    	//figure out how much input we have
    	int numBlocks = (bufferOffset + inputLen) / blockSize;
        int result = numBlocks * blockSize;
        if (result > output.length - outputOffset) { //if it doesn't fit into output array
            throw new ShortBufferException();
         }
        //if there isn't enough data to make one block, just put it in the buffer
        if (numBlocks == 0) {
        	System.arraycopy(input, inputOffset, buffer, bufferOffset, inputLen);
            bufferOffset += inputLen;
            return 0;
        }
        //if there are one or more blocks, process each block
        byte[] block = new byte[blockSize];
        int blockOffset = 0;
        for (int i = 0; i < numBlocks; i++) {
        	//fill the block from buffer and input
        	int buffLen = 0; //# of bytes to come form buffer
        	if (buffer.length - bufferOffset > blockSize) {
        		buffLen = blockSize;
        		blockOffset = blockSize;
        	}
        	else {
        		buffLen = buffer.length - bufferOffset;
        		blockOffset = buffLen;
        	}
        	int inLen = blockSize - buffLen;
        	//copy from buffer
        	System.arraycopy(buffer, bufferOffset, block, 0,  buffLen);
        	//copy from input
        	System.arraycopy(input, inputOffset, block, blockOffset, inLen);
        	bufferOffset += buffLen;
        	inputOffset += inLen;
        	//if encryption, XOR with IV or ciphertext
        	if (MODE == Cipher.ENCRYPT_MODE) {
        		if (do_cbc) {
        			if (prev == null) {
        				for (int j = 0; j < block.length; j++) {
        					block[j] = (byte) (block[j] ^ iv[j]);
        				}
        			}
        			else {
        				for (int j = 0; j < block.length; j++) {
        					block[j] = (byte) (block[j] ^ prev[j]);
        				}
        			}
        		}
        		//then encrypt and store the result
        		byte[] res = aes.encrypt(block);
        		byte[] temp = new byte[res.length + resultText.length];
        		System.arraycopy(resultText, 0, temp, 0,  resultText.length);
        		System.arraycopy(res, 0, temp, resultText.length, res.length);
        		resultText = temp;
        		//store ciphertext for chaining
        		prev = res;
        	}
        	else if (MODE == Cipher.DECRYPT_MODE) {
        		//if decryption, decrypt
        		byte[] res = aes.decrypt(block);
        		if (do_cbc) { 
        			//then with iv or prev to get plaintext
        			if (prev == null) {
        				for (int j = 0; j < block.length; j++) {
        					block[j] = (byte) (block[j] ^ iv[j]);
        				}
        			}
        			else {
        				for (int j = 0; j < block.length; j++) {
        					block[j] = (byte) (block[j] ^ prev[j]);
        				}
        			}
        			prev = block; //store last ciphertext for chaining
        		}
        		//store plaintext
        		byte[] temp = new byte[res.length + resultText.length];
        		System.arraycopy(resultText, 0, temp, 0,  resultText.length);
        		System.arraycopy(res, 0, temp, resultText.length, res.length);
        		resultText = temp;
        	}
        }
        
        //put any leftovers in the buffer
        if (((bufferOffset + inputLen) - result) > 0) {
        	System.arraycopy(input, inputOffset, buffer, bufferOffset, (bufferOffset + inputLen) - result);
        	bufferOffset += (bufferOffset + inputLen) - result;
        }
        
        //return length of data processed
        return result;
    }
    
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    	try {
    		byte[] temp = new byte[engineGetOutputSize(inputLen)];
    		int len = engineDoFinal(input, inputOffset, inputLen, temp, 0);
    		return Arrays.copyOf(temp, len);
    	} catch (ShortBufferException e) {
    		System.err.println("Internal Error: " + e);
    		return null;
    	}
    }
    
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    	/**
    	 * Implement me.
    	 */
    	//put all of the result in output? 
    }
    
}
