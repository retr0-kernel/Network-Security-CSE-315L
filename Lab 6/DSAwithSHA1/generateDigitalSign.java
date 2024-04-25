import java.io.*;  
import java.security.*;  
public class generateDigitalSign  {  
    public static void main(String args[]) {  
        if (args.length != 1) {  
        System.out.println("Usage: digital.txt");  
    }  
        else try {  
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");  
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");  
            keyGen.initialize(1024, random);  
            KeyPair pair = keyGen.generateKeyPair();  
            PrivateKey priv = pair.getPrivate();  
            PublicKey pub = pair.getPublic();  
            Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");   
            dsa.initSign(priv);  
            FileInputStream fis = new FileInputStream("C:\\Users\\krish\\OneDrive\\Desktop\\6th Sem\\Network Security CSE 315L\\Lab 6\\digital.txt");  
            BufferedInputStream bufin = new BufferedInputStream(fis);  
            byte[] buffer = new byte[1024];  
            int len;  
            while (bufin.available() != 0) {  
                len = bufin.read(buffer);  
                dsa.update(buffer, 0, len);  
            };  
            bufin.close();    
            byte[] realSig = dsa.sign();  
            FileOutputStream sigfos = new FileOutputStream("C:\\Users\\krish\\OneDrive\\Desktop\\6th Sem\\Network Security CSE 315L\\Lab 6\\signature.txt");  
            sigfos.write(realSig);  
            sigfos.close();  
            byte[] key = pub.getEncoded();  
            FileOutputStream keyfos = new FileOutputStream("C:\\Users\\krish\\OneDrive\\Desktop\\6th Sem\\Network Security CSE 315L\\Lab 6\\publickey.txt");  
            keyfos.write(key);  
            keyfos.close();  
            }   
        catch (Exception e) {  
            System.err.println("Caught exception " + e.toString());  
        }  
    };  
}  