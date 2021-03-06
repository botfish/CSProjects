
package csec2013;

import java.security.Provider;

/**
 * A Provider that links the AES cipher from Project 1 into the JCE
 */
public class CSec2013Prov extends Provider {
    /**
     * Constructor.
     *
     * Use this with java.security.Security.insertProviderAt() to install this
     * provider into your Chat project.
     */
    public CSec2013Prov() {
        super("CSec2013", 1.0, "Provider for AES from Project 1.");

        put("Cipher.AES", "csec2013.AESCipher");
    }
}
