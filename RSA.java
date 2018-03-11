import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import static java.nio.charset.StandardCharsets.UTF_8;

public class RSA{
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        return pair;
    }

    public static KeyPair getKeyPairFromKeyStore() throws Exception {
        //Generated with:
        //  keytool -genkeypair -alias mykey -storepass s3cr3t -keypass s3cr3t -keyalg RSA -keystore keystore.jks

        InputStream ins = RSA.class.getResourceAsStream("/keystore.jks");

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, "s3cr3t".toCharArray());   //Keystore password
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection("s3cr3t".toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("mykey", keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate("mykey");
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    public static String encrypt(String plainText, PublicKey publickey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publickey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }
    
    public static String encrypt(String plainText, PrivateKey privateKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }
    
    public static String decrypt(String cipherText, PublicKey publickey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, publickey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();
        
        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        
        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }
    
   
    public static String getStringPubk(KeyPair pair)  
   {      PublicKey pub = pair.getPublic();
          byte[] pubBytes = pub.getEncoded();
          String pubk=Base64.getEncoder().encodeToString(pubBytes) ;
          return pubk;
   }
    
    public static PublicKey getPubk(String pubk) throws InvalidKeySpecException, NoSuchAlgorithmException  
    {       byte[] pubBytes2 =Base64.getDecoder().decode(pubk);
            PublicKey  publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubBytes2));
           return publicKey;
    } 
 
    
    public static void main(String[] abcd) throws Exception
    {  KeyPair pair=generateKeyPair();
       String a="abc";
       String cipher;
       
       System.out.print(sign(a, pair.getPrivate()));
    }
    
 }
