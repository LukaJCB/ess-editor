package org.ltj.crypto.test;

import com.google.gson.Gson;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.ltj.cryptoeditor.crypto.encryption.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;

public class BCCryptographerTest {

    @Before
    public void initialize() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public final static String input = "1234567812345678";
    private final static SecretKey aesKey = new SecretKeySpec(new byte[]{
            45, 9, 89, 93,
            39, -5, 2, 38,
            52, -111, -91, -118,
            0, 121, 110, 35
    }, "AES");
    private final static SecretKey desKey = new SecretKeySpec(new byte[]{
            45, 9, 89, 93,
            39, -5, 2, 38
    }, "DES");


    @Test
    public void testRsa() throws Exception {

        BCCryptographer cryptographer = BCCryptographer.getInstance();

        RSAPublicKey publicKey = cryptographer.generatePublicKey("d46f473a2d746537de2056ae3092c451");
        RSAPrivateKey privateKey = cryptographer.generatePrivateKey("d46f473a2d746537de2056ae3092c451","57791d5430d593164082036ad8b29fb1");

        String cipherText = cryptographer.encryptRsa(input,publicKey);
        Assert.assertThat(input, not(equalTo(cipherText)));

        String plainText = cryptographer.decryptRsa(cipherText,privateKey);

        Assert.assertThat(input, is(equalTo(plainText)));
    }

    @Test
    public void testDigestNoTamper() throws Exception {
        Encryption encryption = new Encryption(EncryptionType.ARC4);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        HashPayload output = cryptographer.encryptWithHash(input,encryption,aesKey);

        HashDecryptionResult result = cryptographer.decryptWithHash(output,encryption,aesKey);
        Assert.assertFalse(result.temperedWith);
        Assert.assertThat(result.plainText, is(equalTo(input)));

    }

    @Test
    public void testDigestTampered() throws Exception {
        Encryption encryption = new Encryption(EncryptionType.ARC4);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        HashPayload output = cryptographer.encryptWithHash(input,encryption,aesKey);

        byte[] tampered = output.cipherText.getBytes();
        tampered[9] ^= '0' ^ '9';
        HashPayload tamperedPayload = new HashPayload(new String(tampered),output.ctLength);

        HashDecryptionResult result = cryptographer.decryptWithHash(tamperedPayload,encryption,aesKey);
        Assert.assertTrue(result.temperedWith);
        Assert.assertThat(result.plainText, not(equalTo(input)));
    }



    @Test
    public void testSerializationArc4() throws Exception {
        Encryption encryption = new Encryption(EncryptionType.ARC4);

        String password = "password";
        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,password,encryption);

        EncryptedPackage pack = new EncryptedPackage(encryption,output,false,null);
        String json = pack.toJson();
        EncryptedPackage deserialized = EncryptedPackage.fromJson(json);
        Assert.assertTrue(deserialized.encryption.type.isStreamType);
    }

    @Test
    public void testSerializationAes() throws Exception {
        Encryption encryption = new Encryption(EncryptionType.AES,EncryptionMode.GCM);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,encryption,aesKey);

        EncryptedPackage pack = new EncryptedPackage(encryption,output,false,null);
        String json = pack.toJson();
        EncryptedPackage deserialized = EncryptedPackage.fromJson(json);
        Assert.assertTrue(deserialized.encryption.mode.isStreamMode);
    }

    @Test
    public void testPbeAes() throws Exception {


        Encryption encryption = new Encryption(EncryptionType.AES,EncryptionMode.CTR);
        String password = "password";
        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,password,encryption);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,password,encryption);
        Assert.assertThat(input, is(equalTo(decrypted)));

        String falseDecrypted = cryptographer.decrypt(output,"oassword",encryption);
        Assert.assertThat(input, not(equalTo(falseDecrypted)));

    }

    @Test
    public void testPbeDes() throws Exception {


        Encryption encryption = new Encryption(EncryptionType.DES);
        String password = "password";
        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,password,encryption);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,password,encryption);
        Assert.assertThat(input, is(equalTo(decrypted)));

        String falseDecrypted = cryptographer.decrypt(output,"oassword",encryption);
        Assert.assertThat(input, not(equalTo(falseDecrypted)));

    }

    @Test
    public void testPbeArc4() throws Exception {


        Encryption encryption = new Encryption(EncryptionType.ARC4);
        String password = "password";
        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,password,encryption);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,password,encryption);
        Assert.assertThat(input, is(equalTo(decrypted)));

        String falseDecrypted = cryptographer.decrypt(output,"oassword",encryption);
        Assert.assertThat(input, not(equalTo(falseDecrypted)));

    }


    @Test
    public void testAesEcbNoPadding() throws Exception {


        Encryption encryption = new Encryption(EncryptionType.AES);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,encryption,aesKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,aesKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testAesEcbPkcs5() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.AES, EncryptionMode.ECB, EncryptionOptions.PKCS5Padding);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,encryption,aesKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,aesKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testAesEcbPkcs7() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.AES,EncryptionMode.ECB,EncryptionOptions.PKCS7Padding);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
         
        String output = cryptographer.encrypt(input,encryption,aesKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,aesKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testAesCbcPkcs5() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.AES,EncryptionMode.CBC,EncryptionOptions.PKCS5Padding);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,encryption,aesKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,aesKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testAesCbcPkcs7() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.AES,EncryptionMode.CBC,EncryptionOptions.PKCS7Padding);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
         
        String output = cryptographer.encrypt(input,encryption,aesKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,aesKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testAesOfb() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.AES, EncryptionMode.OFB);

        BCCryptographer cryptographer = BCCryptographer.getInstance();

        String output = cryptographer.encrypt(input,encryption,aesKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,aesKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testAesCtr() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.AES, EncryptionMode.CTR);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,encryption,aesKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,aesKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testAesCfb() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.AES, EncryptionMode.CFB);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,encryption,aesKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,aesKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testAesGcm() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.AES, EncryptionMode.GCM);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,encryption,aesKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,aesKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testDesEcbNoPadding() throws Exception {


        Encryption encryption = new Encryption(EncryptionType.DES);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,encryption,desKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,desKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }


    @Test
    public void testDesEcbPkcs5() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.DES,EncryptionMode.ECB,EncryptionOptions.PKCS5Padding);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,encryption,desKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,desKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testDesEcbPkcs7() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.DES,EncryptionMode.ECB,EncryptionOptions.PKCS7Padding);

        BCCryptographer cryptographer = BCCryptographer.getInstance();

        String output = cryptographer.encrypt(input,encryption,desKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,desKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testDesCbcPkcs5() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.DES,EncryptionMode.CBC,EncryptionOptions.PKCS5Padding);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,encryption,desKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,desKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testDesCbcPkcs7() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.DES,EncryptionMode.CBC,EncryptionOptions.PKCS7Padding);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,encryption,desKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,desKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testDesOfb() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.DES, EncryptionMode.OFB);

        BCCryptographer cryptographer = BCCryptographer.getInstance();

        String output = cryptographer.encrypt(input,encryption,desKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,desKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testDesCtr() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.DES, EncryptionMode.CTR);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,encryption,desKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,desKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testDesCfb() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.DES, EncryptionMode.CFB);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,encryption,desKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,desKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }

    @Test
    public void testArc4() throws Exception {

        Encryption encryption = new Encryption(EncryptionType.ARC4);

        BCCryptographer cryptographer = BCCryptographer.getInstance();
        String output = cryptographer.encrypt(input,encryption,aesKey);

        Assert.assertThat(input, not(equalTo(output)));

        String decrypted = cryptographer.decrypt(output,encryption,aesKey);
        Assert.assertThat(input, is(equalTo(decrypted)));

    }


}