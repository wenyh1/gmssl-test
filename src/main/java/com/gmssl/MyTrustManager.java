package com.gmssl;

import javax.net.ssl.X509TrustManager;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

// 参考JDBC
public class MyTrustManager implements X509TrustManager {

    private X509TrustManager origTm = null;
    private CertificateFactory certFactory = null;
    private PKIXParameters validatorParams = null;
    private CertPathValidator validator = null;
    private boolean verifyServerCert = false;

    public MyTrustManager() {
    }

    public MyTrustManager(X509TrustManager tm, boolean verifyServerCertificate) throws CertificateException {
        this.origTm = tm;
        this.verifyServerCert = verifyServerCertificate;

        if (verifyServerCertificate) {
            try {
                Set<TrustAnchor> anch = new HashSet<TrustAnchor>();
                for (X509Certificate cert : tm.getAcceptedIssuers()) {
                    anch.add(new TrustAnchor(cert, null));
                }
                this.validatorParams = new PKIXParameters(anch);
                this.validatorParams.setRevocationEnabled(false);
                this.validator = CertPathValidator.getInstance("PKIX");
                this.certFactory = CertificateFactory.getInstance("X.509");
            } catch (Exception e) {
                throw new CertificateException(e);
            }
        }
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        for (int i = 0; i < chain.length; i++) {
            chain[i].checkValidity();
        }

        if (this.validatorParams != null) {

            X509CertSelector certSelect = new X509CertSelector();
            certSelect.setSerialNumber(chain[0].getSerialNumber());

            System.out.println("## chain Serial:" + chain[0].getSerialNumber());

            // JDBC中 进行认证服务端
            try {
                CertPath certPath = this.certFactory.generateCertPath(Arrays.asList(chain));
                // Validate against truststore
                CertPathValidatorResult result = this.validator.validate(certPath, this.validatorParams);
                // Check expiration for the CA used to validate this path
                ((PKIXCertPathValidatorResult) result).getTrustAnchor().getTrustedCert().checkValidity();

            } catch (InvalidAlgorithmParameterException e) {
                throw new CertificateException("##GMSSL - 1" + e.getMessage(), e);
            } catch (CertPathValidatorException e) {
                throw new CertificateException("##GMSSL - 2" + e.getMessage(), e);
            }
        }

        if (this.verifyServerCert) {
            this.origTm.checkServerTrusted(chain, authType);
        }
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        this.origTm.checkClientTrusted(chain, authType);
    }
}
