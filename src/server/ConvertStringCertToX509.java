package server;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
public class ConvertStringCertToX509 {
	public static X509Certificate[] convertToX509Certarray(String certEntry) throws IOException {		 				
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		InputStream in = null;
        X509Certificate cert = null;
        try {
        	byte[] certEntryBytes = Base64.getDecoder().decode(certEntry);
            in = new ByteArrayInputStream(certEntryBytes);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider()); 
            cert = (X509Certificate) certFactory.generateCertificate(in);
            System.out.println("I am converting cert from string to X509 format. THe converted cert is:   "+cert);            
        } catch (CertificateException ex) {
        	ex.getMessage();
        	return new X509Certificate[]{}; 
        } finally {
            if (in != null) {
                    in.close();
            }
        }
        return new X509Certificate[]{cert};
    }
	public static X509Certificate convertToX509Cert(String certEntry) throws IOException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		InputStream in = null;
        X509Certificate cert = null;
        try {
        	CertificateFactory certFactory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider()); 
            byte[] certEntryBytes = Base64.getEncoder().encode(certEntry.getBytes());
            System.out.println("I am converting cert from string to X509 format. THe converted byte format cert is:   "+certEntryBytes);
            in = new ByteArrayInputStream(certEntryBytes);
            cert = (X509Certificate) certFactory.generateCertificate(in);
            System.out.println("I am converting cert from string to X509 format. THe converted cert is:   "+cert);
            PublicKey pubkey = cert.getPublicKey();
            System.out.println(pubkey);
            return cert;
        } catch (CertificateException ex) {
        	ex.getMessage(); 
        } finally {
            if (in != null) {
                    in.close();
            }
        }
        return cert;
    }


}
