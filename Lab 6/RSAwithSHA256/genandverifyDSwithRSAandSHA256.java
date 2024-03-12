import java.security.KeyPair;  
import java.security.KeyPairGenerator;  
import java.security.PrivateKey;  
import java.security.PublicKey;  
import java.security.SecureRandom;  
import java.security.Signature;  
// import java.util.Scanner;  
// import javax.xml.bind.DatatypeConverter;  

public class genandverifyDSwithRSAandSHA256  
{  
    private static final String  
    SIGNING_ALGORITHM = "SHA256withRSA";  
    private static final String RSA = "RSA";  
    // private static Scanner sc;  
    public static byte[] createDigitalSignature(byte[] input, PrivateKey Key) throws Exception  {  
        Signature sig = Signature.getInstance(SIGNING_ALGORITHM);  
        sig.initSign(Key);  
        sig.update(input);  
        return sig.sign();  
    }
  
    public static KeyPair generateRSAKeyPair() throws Exception  {  
        SecureRandom sr = new SecureRandom();  
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);  
        kpg.initialize(2048, sr);  
        return kpg.generateKeyPair();  
    }  
    public static boolean verifyDigitalSignature(byte[] input, byte[] signatureToVerify, PublicKey key) throws Exception  {  
        Signature sig = Signature.getInstance(SIGNING_ALGORITHM);  
        sig.initVerify(key);  
        sig.update(input);  
        return sig.verify(signatureToVerify);  
    }  

    public static void main(String args[]) throws Exception  {  
        String input = "Java is an" + "object-oriented language";  
        KeyPair keyPair = generateRSAKeyPair();  
        byte[] sig = createDigitalSignature(input.getBytes(), keyPair.getPrivate());  
        System.out.println("Signature Value:\n " + sig);  
        System.out.println("Verification: "+ verifyDigitalSignature(input.getBytes(), sig, keyPair.getPublic()));  
    }  
}  