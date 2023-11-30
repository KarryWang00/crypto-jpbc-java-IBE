package org.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

/**
 * @author karry
 * @date 2023/11/30 14:41
 */
public class IBE {
    /**
     * write properties file to locally
     * @param prop
     * @param fileName
     */
    public static void storePropToFile(Properties prop, String fileName){
        try(FileOutputStream out = new FileOutputStream(fileName)){
            prop.store(out, null);
        }
        catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    /**
     * read prop local file
     * @param fileName
     * @return
     */
    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)){
            prop.load(in);
        }
        catch (IOException e){
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }

    /**
     * compute Hash value
     * @param content
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static void setup(String pairingParametersFileName, String pkFileName, String mskFileName){
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        // select random x
        Element x = bp.getZr().newRandomElement().getImmutable();

        // create Properties Object
        Properties mskProp = new Properties();
        // x is big Integer，use x.toBigInteger().toString()，but it will be garbled
        mskProp.setProperty("x", Base64.getEncoder().encodeToString(x.toBytes()));

        storePropToFile(mskProp,mskFileName);

        // select g \in G_1 as its generator
        Element g = bp.getG1().newRandomElement().getImmutable();
        // compute g^x
        Element gx = g.powZn(x).getImmutable();
        Properties pkProp = new Properties();
        // use <g, g^x> as system public key
        pkProp.setProperty("g", Base64.getEncoder().encodeToString(g.toBytes()));
        pkProp.setProperty("gx", Base64.getEncoder().encodeToString(gx.toBytes()));
        storePropToFile(pkProp,pkFileName);
    }

    public static void keygen(String pairingParametersFileName, String id, String mskFileName, String skFileName) throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        // compute id hash
        byte[] idHash = sha1(id);
        // Map it to G1 group element
        Element QID = bp.getG1().newElementFromHash(idHash,0,idHash.length).getImmutable();

        // read system private key
        Properties mksProp = loadPropFromFile(mskFileName);
        String xString = mksProp.getProperty("x");
        Element x = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xString)).getImmutable();
        // compute id corresponding private key is Q_id^x
        Element sk = QID.powZn(x).getImmutable();

        // write id private key into properties file
        Properties skProp = new Properties();
        skProp.setProperty("sk", Base64.getEncoder().encodeToString(sk.toBytes()));
        storePropToFile(skProp, skFileName);
    }

    public static void encrypt(String pairingParametersFileName, String message, String id, String pkFileName, String ctFileName) throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        // compute QID
        byte[] idHash = sha1(id);
        Element QID = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();

        // read user public key
        Properties pkProp = loadPropFromFile(pkFileName);
        String gString = pkProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String gxString = pkProp.getProperty("gx");
        Element gx = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gxString)).getImmutable();

        // select random r
        Element r = bp.getZr().newRandomElement().getImmutable();
        // compute ciphertext C_1 = g^r, exponent arithmetic
        Element C1 = g.powZn(r).getImmutable();
        // compute e(Q_{ID},g^x)^r
        Element gID = bp.pairing(QID,gx).powZn(r).getImmutable();

        String gIDString = new String(gID.toBytes());
        byte[] HgID = sha1(gIDString);
        byte[] messageByte = message.getBytes();

        byte[] C2 = new byte[messageByte.length];
        for (int i = 0; i< messageByte.length; i++){
            // ^ Xor operation
            C2[i] = (byte)(messageByte[i] ^ HgID[i]);
            System.out.println(C2[i]);
        }


        // write <C1,C2> ciphertext write into properties ct file
        Properties ctProp = new Properties();
        ctProp.setProperty("C1",Base64.getEncoder().encodeToString(C1.toBytes()));
        ctProp.setProperty("C2",Base64.getEncoder().encodeToString(C2));
        storePropToFile(ctProp,ctFileName);
    }

    public static String decrypt(String pairingParametersFileName, String ctFileName, String pkFileName, String skFileName) throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties skProp = loadPropFromFile(skFileName);
        String skString = skProp.getProperty("sk");
        Element sk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skString)).getImmutable();

        Properties ctProp = loadPropFromFile(ctFileName);
        String C1String = ctProp.getProperty("C1");
        Element C1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1String)).getImmutable();
        String C2String = ctProp.getProperty("C2");
        byte[] C2 = Base64.getDecoder().decode(C2String);

        Element gID = bp.pairing(sk, C1).getImmutable();

        String gIDString = new String(gID.toBytes());
        byte[] HgID = sha1(gIDString);
        byte[] res = new byte[C2.length];
        for (int i = 0; i < C2.length; i++){
            res[i] = (byte)(C2[i] ^ HgID[i]);
        }
        return new String(res);
    }


    public static void main(String[] args) throws Exception {

        // test case
        String idBob = "bob@example.com";
        String idAlice = "alice@example.com";
        String message = "I hate you";

        String dir = "data/";
        String pairingParametersFileName = "a.properties";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String ctFileName = dir + "ct.properties";

        setup(pairingParametersFileName, pkFileName, mskFileName);

        keygen(pairingParametersFileName, idBob, mskFileName, skFileName);

        encrypt(pairingParametersFileName, message, idBob, pkFileName, ctFileName);

        String res = decrypt(pairingParametersFileName, ctFileName, pkFileName, skFileName);

        System.out.println(res);
    }
}
