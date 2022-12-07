import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class LicenseManager {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private final String KEYS_PATH = "../keys/";
    private byte[] digitalSignature;

    public LicenseManager() {
        System.out.println("LicenseManager service started...");
    }

    public void requestServer(byte[] encryptedLicense) {
        System.out.println("Server is being requested...");

        setPublicKey();
        setPrivateKey();
        System.out.println("Server -- Incoming Encrypted Text: "+ Base64.getEncoder().encodeToString(encryptedLicense));
        String decryptedMessage = decryptText(encryptedLicense);
        System.out.println("Server -- Decrypted Text: "+ decryptedMessage);

        byte[] digest = hashing(decryptedMessage);
        BigInteger bigInt = new BigInteger(1, digest);
        String hashText = bigInt.toString(16);
        System.out.println("Server -- MD5 Plain License Text: " + hashText);

        createDigitalSignature(digest);
    }

    public void createDigitalSignature(byte[] bytesOfText){
        try{
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(bytesOfText);
            byte[] signatureBytes = signature.sign();
            setDigitalSignature(signatureBytes);
            System.out.println("Server -- Digital Signature: "+ Base64.getEncoder().encodeToString(signatureBytes));
        }catch(NoSuchAlgorithmException | InvalidKeyException | SignatureException exception){
            exception.printStackTrace();
        }

    }

    public byte[] hashing(String textToBeHashed){
        try{
            //Hashing
;           MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(textToBeHashed.getBytes());
            return md.digest();
        }catch (NoSuchAlgorithmException exception) {
            exception.printStackTrace();
        }
        return null;
    }

    public String decryptText(byte[] encryptedText){
        try{
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedText);

            return new String(decryptedMessageBytes, StandardCharsets.UTF_8);
        }catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException |
                IllegalBlockSizeException exception) {
            exception.printStackTrace();
            return "";
        }
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey() {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(KEYS_PATH + "private.key"));
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            this.privateKey = kf.generatePrivate(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey() {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(KEYS_PATH + "public.key"));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            this.publicKey = kf.generatePublic(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    public byte[] getDigitalSignature() {
        return digitalSignature;
    }

    public void setDigitalSignature(byte[] digitalSignature) {
        this.digitalSignature = digitalSignature;
    }
}
