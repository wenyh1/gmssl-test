package com.gmssl;

import com.other.gmssl.TrustAllManager;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class KeyUtil {
    public static class KeyManagerUtil {

        public static KeyManager[] serverKeyManagersJKS() throws Exception {
            String filepath = System.getProperty("user.dir") +"/src/main/java/com/gmssl/skeystore/sm2.action.both.jks";
            String pwd = "12345678";
            return keyManagersJKS(filepath, pwd);
        }

        public static KeyManager[] serverKeyManagersPFX() throws Exception {
            String pfxfile = System.getProperty("user.dir") +"/src/main/java/com/gmssl/skeystore/sm2.action.both.pfx";
            String pwd = "12345678";
            return keyManagersPFX(pfxfile, pwd);
        }

        public static KeyManager[] clientKeyManagersJKS() throws Exception {
            String filepath = System.getProperty("user.dir") +"/src/main/java/com/gmssl/ckeystore/sm2.action.both.jks";
            String pwd = "12345678";
            return keyManagersJKS(filepath, pwd);
        }

        public static KeyManager[] clientKeyManagersPFX() throws Exception {
            String pfxfile = System.getProperty("user.dir") +"/src/main/java/com/gmssl/ckeystore/sm2.action.both.pfx";
            String pwd = "12345678";
            return keyManagersPFX(pfxfile, pwd);
        }

        private static KeyManager[] keyManagersPFX(String filepath, String pwd) throws Exception {
            KeyStore pfx = KeyStore.getInstance("PKCS12", "GMJSSE");
            InputStream keyStoreIS = new FileInputStream(filepath);
            try {
                pfx.load(new FileInputStream(filepath), pwd.toCharArray());
            } finally {
                keyStoreIS.close();
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(pfx, pwd.toCharArray());
            return kmf.getKeyManagers();
        }

        private static KeyManager[] keyManagersJKS(String filepath, String pwd) throws Exception {
            KeyStore pfx = KeyStore.getInstance("JKS");
            InputStream keyStoreIS = new FileInputStream(filepath);
            try {
                pfx.load(new FileInputStream(filepath), pwd.toCharArray());
            } finally {
                keyStoreIS.close();
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(pfx, pwd.toCharArray());
            return kmf.getKeyManagers();
        }
    }

    public static class TrustMangerUtil {

        public static TrustManager[] serverTrustMangerJKS() throws Exception {
            return null;
        }

        public static TrustManager[] serverTrustMangerPFX() throws Exception {
            return new TrustAllManager[]{new TrustAllManager()};
        }

        public static TrustManager[] clientTrustMangerJKS() throws Exception {
            return null;
        }

        public static TrustManager[] clientTrustMangerPFX() throws Exception {
            String rcaFile = System.getProperty("user.dir") +"/src/main/java/com/gmssl/ckeystore/sm2.rca.pem";
            String ocaFile = System.getProperty("user.dir") +"/src/main/java/com/gmssl/ckeystore/sm2.oca.pem";
            return trustMangerPFX(rcaFile, ocaFile);
            // return new TrustAllManager[]{new TrustAllManager()};
        }

        private static TrustManager[] trustMangerPFX(String rcaFile, String ocaFile) throws Exception {
            KeyStore trustKeyStore = KeyStore.getInstance("PKCS12");
            trustKeyStore.load(null);
            FileInputStream fin = new FileInputStream(ocaFile);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate oca = (X509Certificate) cf.generateCertificate(fin);
            trustKeyStore.setCertificateEntry("oca", oca);
            fin = new FileInputStream(rcaFile);
            X509Certificate rca = (X509Certificate) cf.generateCertificate(fin);
            trustKeyStore.setCertificateEntry("rca", rca);

            TrustManagerFactory trustFactory = TrustManagerFactory.getInstance("SunX509");
            trustFactory.init(trustKeyStore);

            TrustManager[] origTms = trustFactory.getTrustManagers();
            return origTms;
        }

        private static TrustManager[] trustMangerJKS(String filepath, String pwd) throws Exception {
            KeyStore trustStore = KeyStore.getInstance("JKS");
            InputStream trustStoreIS = new FileInputStream(filepath);
            try {
                trustStore.load(trustStoreIS, pwd.toCharArray());
            } finally {
                trustStoreIS.close();
            }
            TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustFactory.init(trustStore);
            return trustFactory.getTrustManagers();
        }
    }
}
