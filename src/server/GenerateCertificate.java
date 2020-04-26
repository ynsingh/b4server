package server ; 
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Calendar;
import java.util.Hashtable;
import java.util.Vector;
import dao.DatabaseConnection;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.sql.SQLException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V3CertificateGenerator;
//Lt Col Ankit Singhal Dated 22 May 2019 ; 1051 Hrs
//This function generates X.509 certificate using the user's credentials
// Use of bouncy castle API has been done for interoperability between Eclipse and latest versions of java
@SuppressWarnings("deprecation")
public class GenerateCertificate {	
	private static final String Emailid = "b4server@iitk.ac.in";		
    private static final String organizationalUnit = "IIT KANPUR";
    private static final String organization = "EE DEPT";
    private static final String city = "KANPUR";
    private static final String state = "UTTAR PRADESH";
    private static final String country = "IN";
    private static final String alias1 = "tomcat";
    static final String password	=	Gui.getkeystorepass();
    static final char[] keyPass = password.toCharArray();
	public static PrivateKey privKey;
	static KeyPair keypair = null;
    static X509Certificate createSelfSignedCert()throws Exception {
    		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    		try{
    			KeyStore keyStore = null;
            try {
            	keyStore = KeyStore.getInstance("JKS");
            } catch (KeyStoreException e1) {
            	e1.printStackTrace();
            }      
            try {
            	keyStore.load(null,keyPass );
            } catch (NoSuchAlgorithmException e1) {
            	e1.printStackTrace();
            } catch (CertificateException e1) {
            	e1.printStackTrace();
            }   
       		try {		
       			keypair = generateRSAKeyPair();
       		} catch (Exception e) {
       			e.printStackTrace();
       		}		
       		System.out.println(keypair); 
       		PublicKey pubKey = null;
       		pubKey = keypair.getPublic(); 
       		final long validity = 365;
       		X509V3CertificateGenerator x500Name = new X509V3CertificateGenerator();
       		Vector<ASN1ObjectIdentifier> order = new Vector<>();
       		Hashtable<ASN1ObjectIdentifier, String> attributeMap = new Hashtable<>();
       		attributeMap.put(X509Name.CN, Emailid);
       		order.add(X509Name.CN);
       		attributeMap.put(X509Name.OU, organizationalUnit);
       		order.add(X509Name.OU);
       		attributeMap.put(X509Name.O, organization);
       		order.add(X509Name.O);
            attributeMap.put(X509Name.L, city);
            order.add(X509Name.L);
            attributeMap.put(X509Name.ST, state);
            order.add(X509Name.ST);
            attributeMap.put(X509Name.C, country);
            order.add(X509Name.C);      
            X509Name issuerDN = new X509Name(order, attributeMap);
            Calendar c = Calendar.getInstance();
            x500Name.setNotBefore(c.getTime());
            c.add(Calendar.YEAR, 1);
            x500Name.setNotAfter(c.getTime());
            x500Name.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
            x500Name.setSignatureAlgorithm("SHA256WithRSAEncryption");
            x500Name.setIssuerDN(issuerDN);
            x500Name.setSubjectDN(issuerDN);
            x500Name.setPublicKey(pubKey);      
            //x500Name.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            //x500Name.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            //x500Name.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
            privKey =   keypair.getPrivate();            
            System.out.println("key pair is:		" + keypair);
            System.out.println("private key  is:	" + privKey);
            System.out.println("public key  is:    " + pubKey);
            System.out.println("alias  is:		" + alias1);
            byte[] bprivkey = privKey.getEncoded();
            String sprivate	=	new String(Base64.encode(bprivkey));
            System.out.println("binary private key =" + bprivkey );
            keystore_save adam = new keystore_save();
            String path = properties_access.read_property("server.properties","home" );
            adam.dumpKeyPair(keypair);
            adam.SaveKeyPair(path, keypair);
            //keypair.generate(1024);
            try {
            	DatabaseConnection.keytoDb("null", Emailid, sprivate, pubKey, validity ,organizationalUnit, organization, city, state, country,alias1, keyPass);
            } catch (ClassNotFoundException e2) {
            	// TODO Auto-generated catch block
            	e2.printStackTrace();
            } catch (SQLException e2) {
            	// TODO Auto-generated catch block
            	e2.printStackTrace();
            }       
        X509Certificate[] chain = new X509Certificate[1];
        try {
        	chain[0] = x500Name.generateX509Certificate(privKey, "BC");
			System.out.println(" get self chain"+chain[0]);
        } catch (InvalidKeyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (SignatureException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}  catch (NoSuchProviderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}     
       try {
		keyStore.setKeyEntry(alias1, privKey, keyPass, chain);
		System.out.println(" setkey chain"+chain[0]);
	} catch (KeyStoreException e1) {
		// TODO Auto-generated catch block
		e1.printStackTrace();
	}        
        
     FileOutputStream fos = new FileOutputStream("ServerKeyStore.JKS");     
		try {
			keyStore.store(fos, keyPass);
			System.out.println(" store chain"+chain[0]);
		} catch (KeyStoreException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (CertificateException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}        
        try {
			saveKeyStore(keyStore,"KeyStore.JKS", password);
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        System.out.println("new cert saved to keystore");
        return chain[0];
    } catch (IOException e)
    	{e.printStackTrace();}
		return null;        		
     } 
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA","BC");
        kpGen.initialize(2048, new SecureRandom());
        return kpGen.generateKeyPair();
      }
	 static KeyStore createEmptyKeyStore() 
        throws GeneralSecurityException, IOException { 
	       KeyStore ks = KeyStore.getInstance("JKS"); 
		   ks.load(null, null); // initialize 
		   return ks; 
	 } 		 
    static void saveKeyStore(KeyStore ks, String filename, String password) 
		    throws GeneralSecurityException, IOException { 
		    FileOutputStream out = new FileOutputStream(filename); 
		    try { 
		      ks.store(out, password.toCharArray()); 
		    } finally { 
		      out.close(); 
		    } 
		  } 		 
    public static void createKeyStore(String filename, String password, String alias, Key privateKey, Certificate cert) 
		    throws GeneralSecurityException, IOException { 
		    KeyStore ks = createEmptyKeyStore(); 
		    ks.setKeyEntry(alias1, privateKey, password.toCharArray(), 
		                   new Certificate[]{cert}); 
		    saveKeyStore(ks, filename, password); 
    } 		 
		  /**
		   * Creates a keystore with a single key and saves it to a file. 
		   *  
		   * @param filename String file to save 
		   * @param password String store password to set on keystore 
		   * @param keyPassword String key password to set on key 
		   * @param alias String alias to use for the key 
		   * @param privateKey Key to save in keystore 
		   * @param cert Certificate to use as certificate chain associated to key 
		   * @throws GeneralSecurityException for any error with the security APIs 
		   * @throws IOException if there is an I/O error saving the file 
		   */ 
		 public static void createKeyStore(String filename, 
		                                    String password, String keyPassword, String alias, 
		                                    Key privateKey, Certificate cert) 
		    throws GeneralSecurityException, IOException { 
		    KeyStore ks = createEmptyKeyStore(); 
		    ks.setKeyEntry(alias, privateKey, keyPassword.toCharArray(), 
		                   new Certificate[]{cert}); 
		    saveKeyStore(ks, filename, password); 
		  } 
		 public static PrivateKey priv() {
 	        if(keypair!=null)privKey = keypair.getPrivate();
 	        return (PrivateKey) privKey;
 	    }
}