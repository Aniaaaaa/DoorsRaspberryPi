import com.pi4j.io.gpio.*;

import org.asynchttpclient.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static java.lang.System.exit;
import static org.asynchttpclient.Dsl.asyncHttpClient;


import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ExecutionException;

import org.asynchttpclient.request.body.multipart.Part;
import org.asynchttpclient.request.body.multipart.StringPart;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import static java.lang.System.out;

public class DoorsOpener {

    private String SERVER_IP_ADDRESS;
    private AsyncHttpClient asyncHttpClient = asyncHttpClient();
    private String SERVER_PUBLIC_KEY;


    private String raspberryIp;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    private JSONArray doors_ids;
    private HashMap<String, GpioPinDigitalOutput> doors_mapping;

    GpioPinDigitalOutput pin0;
    GpioPinDigitalOutput pin1;
    GpioPinDigitalOutput pin2;

    public static void main(String args[]) throws SocketException, InterruptedException {
        for (String arg : args)
            System.out.println(arg);
        if (args[0] == null) {
            System.exit(1);
        }
        new DoorsOpener().run(args[0]);
    }

    private void run(String serverIp) throws InterruptedException{
        GpioController gpio = GpioFactory.getInstance();
        createOutput(gpio);
        checkOutput();
        SERVER_IP_ADDRESS = serverIp;
        getRaspberryPIAddress();
        generateKeys();
        writeDoorsIds();
        getServerPublicKey();
        postRaspberryInformation();
        boolean doLoop = true;
        while (doLoop) {
            try {
                getDoorsState();
                Thread.sleep(5000);
            } catch (Exception e) {
                System.out.println("Exception: " + e);
            }

            if (userTerminates()) {
                doLoop = false;
            }
        }
        System.out.println("Exiting program");
        gpio.shutdown();
        System.exit(0);
    }

    private boolean userTerminates() {
        Scanner scanner = new Scanner(System.in);

        //If you want that user terminates it with 'c' char
        return scanner.nextLine().equals("c");
    }

    private void createOutput(GpioController gpio) {
        pin0 = gpio.provisionDigitalOutputPin(RaspiPin.GPIO_00, "MyLED", PinState.HIGH);
        pin1 = gpio.provisionDigitalOutputPin(RaspiPin.GPIO_01, "MyLED", PinState.HIGH);
        pin2 = gpio.provisionDigitalOutputPin(RaspiPin.GPIO_02, "MyLED", PinState.HIGH);
    }

    public void checkOutput() throws InterruptedException {

        boolean ledOn = true;
        for(int i = 0; i < 3; i++) {
            System.out.println("pin: " + String.valueOf(ledOn));
            pin0.toggle();
            pin1.toggle();
            pin2.toggle();
            ledOn = !ledOn;
            Thread.sleep(10000);
        }
    }

    private void writeDoorsIds() {
        doors_ids = new JSONArray();
        doors_mapping = new HashMap<String, GpioPinDigitalOutput>();
        doors_ids.put("door_0");
        doors_mapping.put("door_0", pin0);
        doors_ids.put("door_1");
        doors_mapping.put("door_1", pin1);
        doors_ids.put("door_2");
        doors_mapping.put("door_2", pin2);


    }

    private void getRaspberryPIAddress() {
        try {
            Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface netint : Collections.list(nets))
                displayInterfaceInformation(netint);
        } catch (SocketException e) {
            System.out.println("Couldn't get raspberry pi ip address");
        }
        System.out.println("Raspberry PI ip: " + raspberryIp);
    }

    private void displayInterfaceInformation(NetworkInterface netint) throws SocketException {
        out.printf("Display name: %s\n", netint.getDisplayName());
        out.printf("Name: %s\n", netint.getName());
        Enumeration<InetAddress> inetAddresses = netint.getInetAddresses();
        for (InetAddress inetAddress : Collections.list(inetAddresses)) {
            if (!inetAddress.isLoopbackAddress() && !inetAddress.isLinkLocalAddress()) {
                if (Collections.list(inetAddresses).size() != 1) {
                    raspberryIp = inetAddress.getHostAddress();
                }
            }
        }
        out.printf("\n");
    }

    private void generateKeys() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");

            // Initialize KeyPairGenerator.
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(2048, random);

            // Generate Key Pairs, a private key and a public key.
            KeyPair keyPair = keyGen.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();

            Base64.Encoder encoder = Base64.getEncoder();
            System.out.println("privateKey: " + encoder.encodeToString(privateKey.getEncoded()));
            System.out.println("publicKey: " + encoder.encodeToString(publicKey.getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    private void openDoor(String id) {
        System.out.println("Open door id: " + id);
        doors_mapping.get(id).high();
    }

    private void closeDoor(String id) {
        System.out.println("CloseDoor id: " + id);
        doors_mapping.get(id).low();
    }


    public void getServerPublicKey() {
        System.out.println("getServerPublicKey");
        String baseUrl = getBaseUrl();
        String relativeUrl = "/nfcData/getPublicKey2048";
        String finalUrl = baseUrl + relativeUrl;
        try {
            Response response = asyncHttpClient
                    .prepareGet(finalUrl)
                    .execute()
                    .get();
            if (response.getStatusCode() == 200) {
                String responseFromServer = response.getResponseBody();
                SERVER_PUBLIC_KEY = responseFromServer;
                System.out.println("Server public key: " + SERVER_PUBLIC_KEY);
            }
        } catch (InterruptedException e) {
            System.out.println("Exception: " + e.getMessage());
        } catch (ExecutionException e) {
            System.out.println("Exception: " + e.getMessage());
        }
    }

    private String getBaseUrl() {
        String baseUrl = "http://" + SERVER_IP_ADDRESS;
        return baseUrl;
    }

    public void postRaspberryInformation() {
        System.out.println("postRaspberryInformation");
        String baseUrl = getBaseUrl();
        String relativeUrl = "/nfcData/installRaspberryDevice";
        String finalUrl = baseUrl + relativeUrl;
        try {
            //createJson
            JSONObject jsonUserData = new JSONObject();
            jsonUserData.put("ip", raspberryIp);

            jsonUserData.put("public_key", publicKey.toString());
            jsonUserData.put("doors_id", doors_ids);
            String message = prepareEncryptedMessage(jsonUserData);
            Part part = new StringPart("postRaspberryInformation", message);

            Response response = asyncHttpClient
                    .preparePost(finalUrl)
                    .addBodyPart(part)
                    .execute()
                    .get();
            if (response.getStatusCode() == 200) {
                String responseFromServer = response.getResponseBody();
                SERVER_PUBLIC_KEY = responseFromServer;
                System.out.println("Server public key: " + SERVER_PUBLIC_KEY);
            }
        } catch (InterruptedException e) {
            System.out.println("Exception: " + e.getMessage());
        } catch (ExecutionException e) {
            System.out.println("Exception: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Exception: " + e);
        }
    }

    private String prepareEncryptedMessage(JSONObject jsonObject) throws NoSuchAlgorithmException, InvalidKeySpecException, JSONException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {

        //String publicKeyString = SERVER_PUBLIC_KEY;
        byte[] publicKeyBytes = Base64.getDecoder().decode(SERVER_PUBLIC_KEY);

        KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or whatever
        PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        String messageToEncrypt = jsonObject.toString();

        // specify mode and padding instead of relying on defaults (use OAEP if available!)
        Cipher encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        // init with the *public key*!

        encrypt.init(Cipher.PUBLIC_KEY, publicKey);
        // encrypt with known character encoding, you should probably use hybrid cryptography instead
        byte[] encryptedMessageBytes = encrypt.doFinal(messageToEncrypt.getBytes(StandardCharsets.UTF_8));
        String encryptedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);

        System.out.println("encrypted message: " + encryptedMessage);
        return encryptedMessage;

    }

    private String decodeMessage(String encryptedMessage, String privateKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {

        byte[] encryptedMessageBytes = Base64.getDecoder().decode(encryptedMessage);

        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);

        KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or whatever

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = kf.generatePrivate(spec);

        Cipher decrypt= Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decrypt.init(Cipher.PRIVATE_KEY, privateKey);

        String decryptedMessage = new String(decrypt.doFinal(encryptedMessageBytes), StandardCharsets.UTF_8);


        return decryptedMessage;
    }

    public void getDoorsState() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        System.out.println("getDoorState");
        String baseUrl = getBaseUrl();
        String relativeUrl = "/nfcData/openTheDoorInformation";
        String finalUrl = baseUrl + relativeUrl;
        try {
            Response response = asyncHttpClient
                    .prepareGet(finalUrl)
                    .execute()
                    .get();
            if (response.getStatusCode() == 200) {
                String responseFromServer = decodeMessage(response.getResponseBody(), Base64.getEncoder().encodeToString(privateKey.getEncoded()));
                JSONObject obj = new JSONObject(responseFromServer);
                JSONArray arr = obj.getJSONArray("doors");
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject doorObj = arr.getJSONObject(i);
                    String id = doorObj.getString("door_id");
                    Boolean door_state = doorObj.getBoolean("door_state");
                    if (door_state) {
                        openDoor(id);
                    } else {
                        closeDoor(id);
                    }
                }
            }
        } catch (InterruptedException e) {
            System.out.println("Exception: " + e.getMessage());
        } catch (ExecutionException e) {
            System.out.println("Exception: " + e.getMessage());
        }
    }
}
