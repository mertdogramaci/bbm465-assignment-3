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

    public LicenseManager(byte[] encryptedLicenseBytes) {
        setPublicKey();
        setPrivateKey();

        try {
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedLicenseBytes);
            String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);

            System.out.println("in License Manager:\t\t" + decryptedMessage);

            // decryptedMessage = "abt$1234-5678-9012$F0:2F:74:15:F1:CD$-455469999$201075710502043";    TODO: for testing

            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(decryptedMessage.getBytes());// decrypt ederek license texte ceviriyoruz ve hashliyoruz
            byte[] digest = md.digest();

            String hashText = Base64.getEncoder().encodeToString(digest);
            System.out.println(hashText);

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(digest);// hashlenmis veiriyi sign ediyoruz
            byte[] signatureBytes = signature.sign();

            setDigitalSignature(signatureBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException |
                 IllegalBlockSizeException | SignatureException exception) {
            exception.printStackTrace();
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
