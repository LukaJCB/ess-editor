package org.ltj.crypto.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.ltj.cryptoeditor.crypto.encryption.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

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