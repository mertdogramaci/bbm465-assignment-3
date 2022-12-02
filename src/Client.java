import java.io.File;

public class Client {
    private static final String LICENSE_FILE_PATH = "license.txt";
    private String publicKey;

    public Client() {

    }

    private static void licenseFileChecker() {
        File licenseFile = new File(LICENSE_FILE_PATH);
        System.out.println(licenseFile.exists());
    }

    public static void main(String[] args) {
        System.out.println("Hello world!");
        licenseFileChecker();
    }
}
