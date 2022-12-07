import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Client {
    private final String LICENSE_FILE_PATH = "license.txt";
    private final String KEYS_PATH = "../keys/";
    private PublicKey publicKey;
    private String username;
    private String serialNumber;
    private String macAddress;
    private String diskSerialNumber;
    private String motherboardSerialNumber;
    private String rawLicense;
    private byte[] encryptedLicense;
    private byte[] hashedLicense;
    private LicenseManager licenseManager;

    public Client() {
        System.out.println("Client started...");

        setProperties();
        licenseFileChecker();
    }

    private void setProperties(){
        setUsername(System.getProperty("user.name"));

        setSerialNumber();

        setMacAddress();
        System.out.println("My MAC: " + getMacAddress());

        setDiskSerialNumber();
        System.out.println("My Disk ID: " + getDiskSerialNumber());

        setMotherboardSerialNumber();
        System.out.println("My Motherboard ID: " + getMotherboardSerialNumber());

        setPublicKey();

        setRawLicense(username + "$" +
                serialNumber + "$" +
                macAddress + "$" +
                diskSerialNumber + "$" +
                motherboardSerialNumber);

        setEncryptedLicense();
        setHashedLicense();
    }

    private void licenseFileChecker() {
        licenseManager = new LicenseManager();

        try {
            File licenseFile = new File(LICENSE_FILE_PATH);

            if (licenseFile.exists()) {
                byte[] licenseText = Files.readAllBytes(Paths.get(LICENSE_FILE_PATH));

                if (verify(licenseText)) {
                    System.out.println("Client -- Succeed. The license is correct.");
                } else {
                    System.out.println("Client -- The license file has been broken!!");
                    managerRequest();
                }
            } else {
                System.out.println("Client -- License File is not found.");
                System.out.println("Client -- Raw License Text: " + getRawLicense());
                System.out.println("Client -- Encrypted License Text: " + Base64.getEncoder().encodeToString(getEncryptedLicense()));

                BigInteger bigIntHashedLicense = new BigInteger(1, getHashedLicense());
                String bigIntHashedLicenseText = bigIntHashedLicense.toString(16);
                System.out.println("Client -- MD5 License Text: " + bigIntHashedLicenseText);

                managerRequest();
            }
        } catch (IOException exception) {
            exception.printStackTrace();
        }
    }

    public String findSerialNumber(String command) {
        String serialNumber = "";

        try {
            Process SerialNumberProcess = Runtime.getRuntime().exec(command);

            InputStreamReader ISR = new InputStreamReader(SerialNumberProcess.getInputStream());
            BufferedReader br = new BufferedReader(ISR);

            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (line.length() < 1 || line.startsWith("SerialNumber")) {
                    continue;
                }
                serialNumber = line;
            }

            br.close();
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }

        return serialNumber;
    }

    public byte[] getEncryptedLicense() {
        return this.encryptedLicense;
    }

    public void setEncryptedLicense() {
        try {
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] secretMessageBytes = rawLicense.getBytes(StandardCharsets.UTF_8);

            this.encryptedLicense = encryptCipher.doFinal(secretMessageBytes);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException |
                BadPaddingException exception) {
            exception.printStackTrace();
        }
    }

    public byte[] getHashedLicense() {
        return hashedLicense;
    }

    public void setHashedLicense() {
        try {
            // Hashing
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(getRawLicense().getBytes());
            this.hashedLicense = md.digest();
        }catch (NoSuchAlgorithmException exception) {
            exception.printStackTrace();
        }

    }

    public void managerRequest() {
        try {
            licenseManager.requestServer(encryptedLicense);
            byte[] response = licenseManager.getDigitalSignature();
            //Verification
            if (verify(response)) {
                System.out.println("Client -- Succeed. The license file content is secured and signed by the server.");
                FileOutputStream outputStream = new FileOutputStream(LICENSE_FILE_PATH);
                outputStream.write(response);
                outputStream.close();
            }
        } catch(IOException exception) {
            exception.printStackTrace();
        }

    }

    public boolean verify(byte[] response){
        try {
            // Verification
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(hashedLicense);
            return signature.verify(response);

        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException exception) {
            return false;
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

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("user_serial.txt"));
            this.serialNumber = reader.readLine();
        } catch (IOException ioException) {
            System.out.println("Please be sure that your serial number file exists in the correct location");
            System.exit(0);
        }
    }

    public String getMacAddress() {
        return macAddress;
    }

    public void setMacAddress() {
        try {
            InetAddress localHost = InetAddress.getLocalHost();
            NetworkInterface networkInterface = NetworkInterface.getByInetAddress(localHost);
            byte[] hardwareAddress = networkInterface.getHardwareAddress();

            String[] hexadecimal = new String[hardwareAddress.length];

            for (int i = 0; i < hardwareAddress.length; i++) {
                hexadecimal[i] = String.format("%02X", hardwareAddress[i]);
            }

            this.macAddress = String.join(":", hexadecimal);
        } catch (UnknownHostException | SocketException exception) {
            exception.printStackTrace();
        }
    }

    public String getDiskSerialNumber() {
        return diskSerialNumber;
    }

    public void setDiskSerialNumber() {
        String command = "wmic diskdrive get serialnumber";
        this.diskSerialNumber = "-"+findSerialNumber(command);
    }

    public String getMotherboardSerialNumber() {
        return motherboardSerialNumber;
    }

    public void setMotherboardSerialNumber() {
        String command = "wmic baseboard get serialnumber";
        this.motherboardSerialNumber = findSerialNumber(command);
    }

    public String getRawLicense() {
        return rawLicense;
    }

    public void setRawLicense(String license) {
        this.rawLicense = license;
    }

    public static void main(String[] args) {
        new Client();
    }
}
