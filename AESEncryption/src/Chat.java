
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Queue;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class Chat {
	
    public static void main(String[] args) {
	parseArgs(new ArrayDeque<String>(Arrays.asList(args)));
	Socket c = null;
	Crypto crypt = null;
	if (mode == SERVER) {
	    try {
		ServerSocket s = new ServerSocket(port);
		c = s.accept();
		//call the server setup method
		crypt = new Crypto();
		crypt.serverKeySetup(c);
		System.out.println("You may begin chatting.");
		
	    } catch (IOException e) {
		System.err.println("There was an error opening the server:");
		System.err.println(e);
		System.exit(-3);
	    } catch (SecurityException e) {
		System.err.println("You are not allowed to open the server:");
		System.err.println(e);
		System.exit(-2);
	    }
	} else if (mode == CLIENT) {
	    try {
		c = new Socket(addr, port);
		//call the client setup method
		crypt = new Crypto();
		crypt.clientKeySetup(c);
		System.out.println("You may begin chatting.");
		
	    } catch (IOException e) {
		System.err.println("There was an error connecting:");
		System.err.println(e);
		System.exit(-3);
	    } catch (SecurityException e) {
		System.err.println("You are not allowed to connect:");
		System.err.println(e);
		System.exit(-2);
	    }
	} else {
	    System.err.println("Please specify the mode.");
	    printUsage();
	    System.exit(-1);
	}
	try {
	    new Thread(new ChatSender(System.in, c.getOutputStream(), crypt)).start();
	    new Thread(new ChatReceiver(c.getInputStream(), System.out, crypt)).start();
	} catch (IOException e) {
	    System.err.println("There was an error setting up data transfer:");
	    System.err.println(e);
	    System.exit(-3);
	}
    }
    private static void parseArgs(Queue<String> args) {
	while (args.peek() != null) {
	    String opt = args.poll();
	    if (opt.equals("-s")) {
		if (mode != UNSPECIFIED) {
		    printUsage();
		    System.exit(-1);
		}
		mode = SERVER;
		parsePort(args);
	    } else if (opt.equals("-c")) {
		if (mode != UNSPECIFIED) {
		    printUsage();
		    System.exit(-1);
		}
		mode = CLIENT;
		parseAddr(args);
		parsePort(args);
	    }
	}
    }
    private static void badPort() {
	System.err.println("Please specify a port between 1 and 65535.");
	printUsage();
	System.exit(-1);
    }
    private static void parsePort(Queue<String> args) {
	String strPort = args.poll();
	if (strPort == null) {
	    badPort();
	}
	try {
	    port = Integer.parseInt(strPort);
	} catch (NumberFormatException e) {
	    badPort();
	}
	if (!(1 <= port && port <= 65535)) {
	    badPort();
	}
    }
    private static void badAddr() {
	System.err.println("Please specify an IP address or host name.");
	printUsage();
	System.exit(-1);
    }
    private static void parseAddr(Queue<String> args) {
	String hostname = args.poll();
	if (hostname == null) {
	    badAddr();
	}
	try {
	    addr = InetAddress.getByName(hostname);
	} catch (UnknownHostException e) {
	    System.err.println("The address '" + hostname + "' is unrecognized or could not be resolved.");
	    badAddr();
	} catch (SecurityException e) {
	    System.err.println("You are not allowed to resolve '" + hostname + "'.");
	    System.exit(-2);
	}
    }
    private static void printUsage() {
	System.err.println("Usage:");
	System.err.println("    java Chat -s PORT");
	System.err.println("    invokes Chat in server mode attempting to listen on PORT.");
	System.err.println("");
	System.err.println("    java Chat -c ADDRESS PORT");
	System.err.println("    invokes Chat in client mode attempting to connect to ADDRESS on PORT.");
    }
    

    private static final byte UNSPECIFIED = 0;
    private static final byte SERVER = 1;
    private static final byte CLIENT = 2;

    private static byte mode = UNSPECIFIED;
    private static InetAddress addr = null;
    private static int port = 0;
}

class ChatSender implements Runnable {
	private Cipher encrypt;
	
    public ChatSender(InputStream screen, OutputStream conn, Crypto c) {
	this.screen = new Scanner(screen);
	this.conn = new PrintStream(conn);
	//get the encryption cipher
    encrypt = c.encryptCipher();
    }
    public void run() {
	while (true) {
	    String line = screen.nextLine(); //plaintext
	    //convert to bytes
	    byte[] plain = line.getBytes();
	    //encrypt the message
	    byte[] ciphertext = null;
	    try {
			ciphertext = encrypt.doFinal(plain);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	    
	    //send the message
	    if (ciphertext != null) {
	    	conn.write(ciphertext, 0, ciphertext.length);
	    }
	}
    }

    private Scanner screen;
    private PrintStream conn;
}

class ChatReceiver implements Runnable {
	private Cipher decrypt;
	
    public ChatReceiver(InputStream conn, OutputStream screen, Crypto c) {
	this.conn = conn;
	this.screen = screen;
	//get the decryption cipher
    decrypt = c.decryptCipher();
    }
    public void run() {
	byte[] b = new byte[1024];
	while (true) {
	    try {
		int len = conn.read(b); //encrypted message
		//decrypt the message
		byte[] plain = new byte[len];
		byte[] arr = new byte[len];
		System.arraycopy(b, 0, arr, 0, len);

		try {
			plain = decrypt.doFinal(arr);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		if (len == -1) break;
			screen.write(plain, 0, len);
			screen.write((byte)'\n');
	    } catch (IOException e) {
		System.err.println("There was an error receiving data:");
		System.err.println(e);
	    }
	}
    }

    private InputStream conn;
    private OutputStream screen;
}
