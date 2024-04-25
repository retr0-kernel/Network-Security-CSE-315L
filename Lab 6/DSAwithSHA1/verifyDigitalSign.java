import java.io.*;  
import java.security.*;  
import java.security.spec.*;  
public class verifyDigitalSign {  
    public static void main(String args[]) {  
        if (args.length != 3) {  
            System.out.println("Usage: publickeyfile signaturefile datafile");  
        }  
        else try {  
            FileInputStream keyfis = new FileInputStream("F:\\Digital Signature Demo\\publickey.txt");  
            byte[] encKey = new byte[keyfis.available()];    
            keyfis.read(encKey);  
            keyfis.close();  
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);  
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");  
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);  
            FileInputStream sigfis = new FileInputStream("F:\\Digital Signature Demo\\signature.txt");  
            byte[] sigToVerify = new byte[sigfis.available()];   
            sigfis.read(sigToVerify );  
            sigfis.close();  
            Signature sig = Signature.getInstance("SHA1withDSA", "SUN");  
            sig.initVerify(pubKey);  
            FileInputStream datafis = new FileInputStream("F:\\Digital Signature Demo\\digital.txt");  
            BufferedInputStream bufin = new BufferedInputStream(datafis);  
            byte[] buffer = new byte[1024];  
            int len;  
            while (bufin.available() != 0) {  
                len = bufin.read(buffer);  
                sig.update(buffer, 0, len);  
            };  
            bufin.close();  
            boolean verifies = sig.verify(sigToVerify);  
            System.out.println("signature verifies: " + verifies);  
        }   
        catch (Exception e) {  
            System.err.println("Caught exception " + e.toString());  
        };  
    }  
}  