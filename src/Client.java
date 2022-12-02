import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Client {
    private final String LICENSE_FILE_PATH = "license.txt";
    private final String KEYS_PATH = "keys/";
    private PublicKey publicKey;
    private String username;
    private String serialNumber;
    private String macAddress;
    private String diskSerialNumber;
    private String motherboardSerialNumber;
    private String license;

    public Client() {
        setUsername(System.getProperty("user.name"));

        licenseFileChecker();

        setLicense(username + "$" +
                serialNumber + "$" +
                macAddress + "$" +
                diskSerialNumber + "$" +
                motherboardSerialNumber);

        System.out.println(getLicense());

        byte[] encryptedLicenseBytes = getEncryptedLicense();

        LicenseManager licenseManager = new LicenseManager(encryptedLicenseBytes);
    }

    private void licenseFileChecker() {
        File licenseFile = new File(LICENSE_FILE_PATH);
        if (licenseFile.exists()) {

        } else {
            setMacAddress();
            setDiskSerialNumber();
            setMotherboardSerialNumber();

            setPublicKey();

        }
    }

    private byte[] getEncryptedLicense() {
        try {
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] secretMessageBytes = license.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedLicenseBytes = encryptCipher.doFinal(secretMessageBytes);

            return encryptedLicenseBytes;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException |
                BadPaddingException exception) {
            exception.printStackTrace();
        }

        return new byte[0];
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

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
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

    public String getLicense() {
        return license;
    }

    public String findSerialNumber(String command){
        String serialNumber = "";

        try {
            Process SerialNumberProcess = Runtime.getRuntime().exec(command);

            InputStreamReader ISR = new InputStreamReader(SerialNumberProcess.getInputStream());
            BufferedReader br = new BufferedReader(ISR);

            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (line.length() < 1 || line.startsWith("SerialNumber")) {
                    continue;
                }
                serialNumber = line.replaceAll("\\s+","");
                break;
            }

            br.close();
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }
        return serialNumber;
    }

    public void setLicense(String license) {
        this.license = license;
    }

    public static void main(String[] args) {
        System.out.println("Hello world!");
        new Client();
    }
}
