package server;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import dao.DatabaseConnection;
import java.security.*;  
//This program was last modified by Lt Col Ankit Singhal on 22 May 2019.
//It variefies the OTP sent to the client and if okay then the client certificate is signed by Server's Private key
//Bouncy Castle API is used to carry out the above function.
/**
 * Servlet implementation class otp_verification
 */
@SuppressWarnings("deprecation")
@WebServlet("/otp_verification")
public class otp_verification extends HttpServlet {
	private static final long serialVersionUID = 1L;
	 
    /**
     * @see HttpServlet#HttpServlet()
     */
    public otp_verification() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		response.getWriter().append("Served at: ").append(request.getContextPath());
		System.out.println(" you are in do get method for otp verification");
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		System.out.println(" you are in do post method for otp verification");
		String reqType=request.getParameter("req");
		KeyStore keyStore = null;
		//Socket socket;
		try {
			keyStore = KeyStore.getInstance("JKS");
		} catch (KeyStoreException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}  
		try {
			keyStore.load(null );
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (CertificateException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		//result=new Vector();
		if(reqType.equals("otpverify"))
		{
        	try{     		
        		System.out.println("OTP verification in Progress");
        		String recdClientOTP =request.getParameter("OTP");
        		String recdClientCertString =request.getParameter("cert");
        		String recdClientCertStringfmbyte =request.getParameter("certstringbyte");
        		X509Certificate[] chain =	ConvertStringCertToX509.convertToX509Certarray(recdClientCertStringfmbyte);
        		recdClientCertString = chain[0].toString();
        		System.out.println("the client cert " + recdClientCertString);
        		String clientEmail = null;
        		Matcher m = Pattern.compile("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+").matcher(recdClientCertString);
        	    while (m.find()) 
        			clientEmail = m.group().toString();
        	    System.out.println("the client email id is " + clientEmail);
        	    System.out.println("The recieved OTP at server is " + recdClientOTP);
        		String SentOtp = DatabaseConnection.fromDb(clientEmail);
        		System.out.println("the sent otp is" + SentOtp);
        		if (recdClientOTP.equals(SentOtp))
        		{        			
        			String ServerCertbyte = DatabaseConnection.CertfromDb("b4server@iitk.ac.in");
        			X509Certificate[] servercert =	ConvertStringCertToX509.convertToX509Certarray(ServerCertbyte);
        			System.out.println("the server cert " + servercert[0].toString());
        			String path = "C:\\tmp";
        			keystore_save adam = new keystore_save();
        			PrivateKey ServerPrivate = DatabaseConnection.PrivkeyfromDb("b4server@iitk.ac.in");
        			X509Certificate signedclientcertificate = createSignedCertificate(chain[0],servercert[0],ServerPrivate);
        			byte[] clientcertbyte = signedclientcertificate.getEncoded();
        		    String clientcert =new String( Base64.getEncoder().encode(clientcertbyte));
        			System.out.println("the signed client cert " + signedclientcertificate.toString());
        			PrintWriter out = response.getWriter();
        			out.println( ServerCertbyte  +"ClientCert" + clientcert);
        		}
        		}	
        		catch(Exception e){ 
        			System.err.println("Got an exception!"+e.toString());
				    System.err.println(e.getMessage());
        	} 
        	//doGet(request, response);
		}
	}
	private X509Certificate createSignedCertificate(X509Certificate cetrificate, X509Certificate issuerCertificate,
			PrivateKey issuerPrivateKey) {
		// TODO Auto-generated method stub
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());  
		try{			
			X509V3CertificateGenerator x500Name = new X509V3CertificateGenerator();
			X509Principal x509Principal = PrincipalUtil.getSubjectX509Principal(cetrificate);
			x500Name.setNotBefore(cetrificate.getNotBefore());
            x500Name.setNotAfter(cetrificate.getNotAfter());
            x500Name.setSerialNumber(cetrificate.getSerialNumber());
            x500Name.setSignatureAlgorithm("SHA256WithRSAEncryption");
            x500Name.setIssuerDN(x509Principal);
            x500Name.setSubjectDN(x509Principal);
            x500Name.setPublicKey(cetrificate.getPublicKey()); 
            X509Certificate clientcert = x500Name.generate(issuerPrivateKey, "BC");
			return clientcert;
        }catch(Exception ex){
        			System.err.println("Got an exception!"+ex.toString());
            ex.printStackTrace();
        }
		return null;
	}
}
