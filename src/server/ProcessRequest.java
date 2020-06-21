package server;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
//import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Base64;

//import javax.mail.MessagingException;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import dao.DatabaseConnection;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
//import server.PeerManager;
import server.ServerUtil;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/*
Last modified by Maj Dushyant Choudhary Dated 22 April 2020 ; 2100 Hrs
This Servlet Class is the api for various tasks like :
    1.Certificate Signature of Newly Generated Certificate,
    2.Certificate Signature of Newly Generated Certificate After Certficate revocation,
    3.Store JKS,
    4.Forgot Password OTP Gen,
    5.Forgot Password OTP Verify,
    6.Certificate Revocation OTP gen,
    7.Certificate Revocation OTP verify,
    8.Certificate Revocation reason
*/

@WebServlet("/ProcessRequest")
public class ProcessRequest extends HttpServlet {
    private static final long serialVersionUID = 1L;
    public ProcessRequest() {
        super();
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.getWriter().append("Served at: ").append(request.getContextPath());
        System.out.println("welcome to I Server. you are in do get method");

        //doPost(request,response);
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException  {

        System.out.println("welcome to I Server. you are in do post method");

        //Retrieving client sent request parameters
        String reqType=request.getParameter("req");

        //result=new Vector();
        PrintWriter out = response.getWriter();

        if(reqType.equals("securechannel")) {
            try {
                System.out.println("Inside Secure Channel");
                //get the hash and random string from the scss side.
                //byte hsccstring = request.getParameter("thedigest");  oldcode,errors resolved below
                String hsccstring = request.getParameter("thedigest");
                byte[] hscc = hsccstring.getBytes();

                //int rkey = request.getParameter("randomkey");  oldcode,errors resolved below
                String rkeystring = request.getParameter("randomkey");
                int rkey = Integer.parseInt(rkeystring);

                //master get the own ip .
                //how to get ip of ms and hardcoded ip getting from property file.

                String msip = "http://202.141.40.218:8443/brihaspati4_mserver";//**existing msip for brashpati****
                //String msip = "http://localhost:8084/b4server";//** updated msip**** confirm***
                // make the hash of (ip of ms + received random key).

                String hsh_strng = msip + rkey;
                byte[] bytesOfMessage = hsh_strng.getBytes("UTF-8");

                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] thedigestmsg  = md.digest(bytesOfMessage);

                // now make the comparision between received hash and own make hash.
                //if(matches) {
                if(Arrays.equals(thedigestmsg,hscc)) {
                    //get the ip of scss(client)
                    String scssip=InetAddress.getByName(request.getRemoteAddr()).toString();

                    //generate own random no.
                    int randomkey =ServerUtil.generateRandomKey();

                    //generate the hash of (ip of scss + own rndom key ) send it to the as a response.
                    String hash_ms_strng = scssip +randomkey;

                    byte[] bytesOfMsg = hash_ms_strng.getBytes("UTF-8");

                    MessageDigest md1 = MessageDigest.getInstance("MD5");
                    byte[] thedigestmsgscss  = md1.digest(bytesOfMsg);

                    String msg = "verify by server";
                    String message = msg + thedigestmsgscss + randomkey;
                    response.setContentLength(message.length());
                }
            } catch(Exception e)
            {
                // server log class to be created and then uncomment
                //ServerLog.log("Exception in login in ProcessRequest class"+e.getMessage()); }
            }
        }


        //get the certificate which is send from sccs server with request.
        //System.out.println("WELCOME TO I SERVER");
        if(reqType.equals("sscccertsign")) { 
            try {
                System.out.println("WELCOME TO I SERVER");

                String recdClientCertString =request.getParameter("cert");// amended
                System.out.println("The recieved certificate at server IN STRING format is"+recdClientCertString);

                // this code extracts email id from client cert recieved at server. uses pattern matching.
                //the client cert used is in string format.// shud be converted to x.509 cert format
                String clientEmail = null;
                Matcher m = Pattern.compile("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+").matcher(recdClientCertString);
                while (m.find())
                    clientEmail = m.group().toString();
                System.out.println("CLIENT EMAIL ID EXTRACTED AT SERVER IS  "+clientEmail);



                // this code segment is used to convert client cert in string format to client cert in x.509 format.
                //--X509Certificate[] recdClientCertX509=ConvertStringCertToX509.convertToX509Certarray(recdClientCertString);
                //--System.out.println("The recieved certificate at server IN X509 format is"+ recdClientCertX509.toString());

                // this code segment extracts client email id from cert in x.509 format. this email id will then be given to send otp method.
               // clientEmail = X500Name.asX500Name(recdClientCertX509.getSubjectX500Principal()).getCommonName();
               // System.out.println("The extracted client emailid at server is"+clientEmail);


                //code segment to send OTP on email
                //for reference to pass values- sendEmail(String fromAddr, String toAddr)
                System.out.println("SENDING EMAIL...");
                String Otp = SendMailTLS.sendEmail("otpsender247@gmail.com",clientEmail);
                //String Otp=String.valueOf(SendMailTLS.generateOTP(8));
                
                System.out.println("OTP SENT TO YOUR EMAIL ID PROVIDED IN CERTIFICATE.CHECK MAIL AND INPUT OTP FOR VERIFICATION");
                System.out.println("Sent Otp is "+ Otp);
                //	byte[] recdClientCertbyte = recdClientCertString.getEncoded();
                //	recdClientCertString = new String(Base64.getEncoder().encode(recdClientCertbyte));
                DatabaseConnection.toDb(Otp, clientEmail, null);
                //boolean status1 = otp(Otp);
                //System.out.println(status1);
                // ******new code to be implemented******
                //recieve  cert for signing from client -  implemented
                //get email id from cert at server side - implemented,store email id in server database - TBD
                //generate OTP - IMPLEMENTED,save OTP in serevr DB - TBD
                //send OTP to user email ,open input box for email - IMPLEMENTED
                //submit OTP by user -TBD
                // match OTP with stored OTP of specific email -TBD
                // if OTP does not match - go back to client
                // if OTP matches -
                //generate node id - hex 160 bit - at server, store in server DB
                //sign cert,add node id to cert
                //return back to client
                //***********

            } catch(Exception e) {
            }
        }
        
        if(reqType.equals("ssccrevokecertsign")) {
            try {
                System.out.println("WELCOME TO I SERVER");

                String recdClientCertString =request.getParameter("cert");// amended
                String deviceid =request.getParameter("deviceid");// amended
                String nodeid =request.getParameter("nodeid");// amended
                String pattern = "yyyy-MM-dd";
                SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);

                String date = simpleDateFormat.format(new Date());
                System.out.println("The recieved certificate at server IN STRING format is"+recdClientCertString);
                String recdClientCertStringfmbyte =request.getParameter("certstringbyte");

                System.out.println("the client cert string byte " + recdClientCertStringfmbyte);
                
                X509Certificate[] chain =	ConvertStringCertToX509.convertToX509Certarray(recdClientCertStringfmbyte);
                recdClientCertString = chain[0].toString();
                //chain[0].getNotAfter();
                // this code extracts email id from client cert recieved at server. uses pattern matching.
                //the client cert used is in string format.// shud be converted to x.509 cert format
                String clientEmail = null;
                Matcher m = Pattern.compile("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+").matcher(recdClientCertString);
                while (m.find())
                    clientEmail = m.group().toString();
                System.out.println("CLIENT EMAIL ID EXTRACTED AT SERVER IS  "+clientEmail);
                
                if(DatabaseConnection.crlverifyEmail(clientEmail))
                {
                    String ServerCertbyte = DatabaseConnection.CertfromDb("b4server@iitk.ac.in");
                    X509Certificate[] servercert =	ConvertStringCertToX509.convertToX509Certarray(ServerCertbyte);
                    System.out.println("the server cert " + servercert[0].toString());
                    String path = "C:\\tmp";
                    keystore_save adam = new keystore_save();
                    //PrivateKey ServerPrivate = DatabaseConnection.PrivkeyfromFile(getServletContext().getRealPath("/WEB-INF/key.txt"));
                    PrivateKey ServerPrivate = DatabaseConnection.PrivkeyfromDb("b4server@iitk.ac.in");
                    //System.out.println("ServerPrivate"+ ServerPrivate);
                    //System.out.println("Otp successfully verified " );
                    //create signed client certificate
                    X509Certificate signedclientcertificate = createSignedCertificate(chain[0],servercert[0],ServerPrivate);
                    byte[] clientcertbyte = signedclientcertificate.getEncoded();
                    String clientcert =new String( Base64.getEncoder().encode(clientcertbyte));
                    System.out.println("the signed client cert " + signedclientcertificate.toString());
                    //Signature Sign = Signature.getInstance("SHA1WithRSA");
                    //Sign.initSign(ServerPrivate);
                    //Sign.update(Base64.getDecoder().decode(recdClientCertStringfmbyte));
                    //byte [] signupdate = Sign.sign();
                    //String signature = new String(signupdate, "UTF-8");
                    //String clientsignedhash	=	new String( Base64.getEncoder().encode(signupdate));
                    //System.out.println("SignedObject:" + clientsignedhash);
                    //System.out.println("SignedObject: in string" +  (so.getSignature()));
                    DatabaseConnection.keystoredelete(clientEmail);
                    DatabaseConnection.keystoretoDb(clientEmail, ServerCertbyte, clientcert,deviceid,nodeid,date,date);
                    
                    String certHash=stringHash(clientcert);
                    DatabaseConnection.crlUpdateCertificate(clientEmail, clientcert, chain[0].getNotAfter().toString(), new SimpleDateFormat("dd-MM-yyyy").format(new Date()),chain[0].getSerialNumber().toString());
                    out.println( ServerCertbyte  +"ClientCert" + clientcert);
                }
                /*
                else
                {
                    out.println("2");
                } */



               
            } catch(Exception e) {
            }
        }
        
        if(reqType.equals("storejks")) 
        {
            try {
                System.out.println("INSIDE STORE JKS");
                String cert=request.getParameter("cert");
                String jks=request.getParameter("jks");
                
                System.out.println("STORE JKS CERT: "+cert);
                System.out.println("STORE JKS: "+jks);
                String clientEmail = null;
                Matcher m = Pattern.compile("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+").matcher(cert);
                while (m.find())
                    clientEmail = m.group().toString();
                System.out.println("STORE JKS EMAIL: "+clientEmail);
               
                DatabaseConnection.jkstoDb(clientEmail, jks);
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(ProcessRequest.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SQLException ex) {
                Logger.getLogger(ProcessRequest.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        if(reqType.equals("forgotpasswordotpgen"))
        {
            String emailid=request.getParameter("emailid");
            System.out.println("SENDING EMAIL...");
            String Otp = SendMailTLS.sendEmail("otpsender247@gmail.com",emailid);
            //String Otp=String.valueOf(SendMailTLS.generateOTP(8));
            System.out.println("OTP SENT TO YOUR EMAIL ID PROVIDED IN CERTIFICATE.CHECK MAIL AND INPUT OTP FOR VERIFICATION");
            System.out.println("Sent Otp is "+ Otp);
            try {
                DatabaseConnection.toKeystoreOTP(Otp, emailid, null);
                out = response.getWriter();
                out.println("OTP SENT");
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SQLException ex) {
                Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
            }
            
        }
        
        if(reqType.equals("forgotpasswordotpverify"))
        {
            try {
            String otp=request.getParameter("otp");
            String emailid=request.getParameter("emailid");
            String SentOtp = DatabaseConnection.fromDb(emailid);
            if(otp.equals(SentOtp))
            {
            DatabaseConnection.keystoredelete(emailid);
            out.println("5");    
            }
            
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SQLException ex) {
            Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        }
        
        if(reqType.equals("certificaterevocationotpgen"))
        {
            String emailid=request.getParameter("emailid");
            System.out.println("SENDING EMAIL...");
            String Otp = SendMailTLS.sendEmail("otpsender247@gmail.com",emailid);
            //String Otp=String.valueOf(SendMailTLS.generateOTP(8));
            System.out.println("OTP SENT TO YOUR EMAIL ID PROVIDED IN CERTIFICATE.CHECK MAIL AND INPUT OTP FOR VERIFICATION");
            System.out.println("Sent Otp is "+ Otp);
            try {
                DatabaseConnection.toKeystoreOTP(Otp, emailid, null);
                out = response.getWriter();
                out.println("OTP SENT");
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SQLException ex) {
                Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
            }
            
        }
        
        if(reqType.equals("certificaterevocationotpverify"))
        {
            try {
            String otp=request.getParameter("otp");
            String emailid=request.getParameter("emailid");
            String SentOtp = DatabaseConnection.fromDb(emailid);
            if(otp.equals(SentOtp))
            {
                String[] verifyEmailKeyStore=DatabaseConnection.keystorefromDb(emailid).split(":::::::");
                if(verifyEmailKeyStore[0]!=null)
                {
                    //DatabaseConnection.keystoredelete(emailid);
                    out.println("6");    
                }
                else
                {
                    out.println("3");
                }
                
            }
            else
            {
                out.println("4");
            }
            
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SQLException ex) {
            Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        }
        
        if(reqType.equals("certificaterevocationreason"))
        {
            String reason=request.getParameter("reason");
            String emailid=request.getParameter("emailid");
            
            try {
                //System.out.println(reason+" "+emailid);
                DatabaseConnection.crltoDb(emailid,null, reason, null,null,null);
                out.println("7");
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(ProcessRequest.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SQLException ex) {
                Logger.getLogger(ProcessRequest.class.getName()).log(Level.SEVERE, null, ex);
            }
            
        
        }
        
        if(reqType.equals("checkcrl"))
        {
            String certsrnum=request.getParameter("certsrno");
            
            boolean isCRLExists=DatabaseConnection.check_crl(certsrnum);
            if(isCRLExists)
            {
             out.println("24");   
            }
            else
            {
             out.println("25");   
            }
        }
        
        if(reqType.equals("checkkeystore"))
        {
            String emailid=request.getParameter("emailid");
            
            boolean isKeyStoreExists=DatabaseConnection.check_keystore(emailid);
            if(isKeyStoreExists)
            {
             out.println("14");   
            }
            else
            {
             out.println("15");   
            }
        }
        
        if(reqType.equals("keystorecheckotpgen"))
        {
            String emailid=request.getParameter("emailid");
            System.out.println("SENDING EMAIL...");
            String Otp = SendMailTLS.sendEmail("otpsender247@gmail.com",emailid);
            //String Otp=String.valueOf(SendMailTLS.generateOTP(8));
            System.out.println("OTP SENT TO YOUR EMAIL ID PROVIDED IN CERTIFICATE.CHECK MAIL AND INPUT OTP FOR VERIFICATION");
            System.out.println("Sent Otp is "+ Otp);
            try {
                DatabaseConnection.toKeystoreOTP(Otp, emailid, null);
                out = response.getWriter();
                out.println("OTP SENT");
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SQLException ex) {
                Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
            }
            
        }
        
        if(reqType.equals("keystorecheckotpverify"))
        {
            System.out.println("INSIDE KEYSTORE CHECK OTP VERIFY");
            try {
            String otp=request.getParameter("otp");
            String emailid=request.getParameter("emailid");
            String device_id=request.getParameter("deviceid");
            String SentOtp = DatabaseConnection.fromDb(emailid);
            if(otp.equals(SentOtp))
            {
                DatabaseConnection.multideviceEntry(emailid,device_id);
                System.out.println("INSIDE KEYSTORE CHECK OTP VERIFICATION COMPLETE");
                //String verifyEmailKeyStore=DatabaseConnection.jksfromDb(emailid);
                String certs = DatabaseConnection.keystorefromDb(emailid);
                String cert[]=certs.split(":::::::");
                out.println(cert[0]  +"ClientCert" + cert[1]);    
            }
            else
            {
                out.println("17");
            }
            
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SQLException ex) {
            Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        }
        
        //doGet(request, response);
    }
    
    private X509Certificate createSignedCertificate(X509Certificate cetrificate, X509Certificate issuerCertificate,PrivateKey issuerPrivateKey) {
        // TODO Auto-generated method stub
        try {
            Principal issuer = issuerCertificate.getSubjectDN();
            System.out.println("issuer   "+  issuer.toString());
            String issuerSigAlg = issuerCertificate.getSigAlgName();

            byte[] inCertBytes = cetrificate.getTBSCertificate();
            System.out.println("a1   ");
            X509CertInfo info = new X509CertInfo(inCertBytes);
            System.out.println("a2   ");
        //    X500Name attr	= (X500Name) issuer;
        //    System.out.println("a4   " + attr);
            // info.delete(X509CertInfo.ISSUER);

            //info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(attr));
            // info.set(X509CertInfo.ISSUER, new CertificateIssuerName(attr));
            // System.out.println("a3   ");
            //System.out.println("issuer   "+  X509CertInfo.ISSUER.toString());
            //No need to add the BasicContraint for leaf cert
            //if(!cetrificate.getSubjectDN().getName().equals("CN=b4server@iitk.ac.in, OU=IIT KANPUR,O=EE DEPT, L=KANPUR, ST=UTTAR PRADESH, C=IN"))
            /*CertificateExtensions exts=new CertificateExtensions();
            System.out.println("a1   ");
             BasicConstraintsExtension bce = new BasicConstraintsExtension(true, -1);
             System.out.println("a2 ");
             exts.set(BasicConstraintsExtension.NAME,new BasicConstraintsExtension(false, bce.getExtensionValue()));
             System.out.println("a3  ");

             info.set(X509CertInfo.EXTENSIONS, exts);
             System.out.println("a4   ");
            */

            X509CertImpl outCert = new X509CertImpl(info);
            outCert.sign(issuerPrivateKey, issuerSigAlg);
            X509Certificate clientcert = outCert;
            return clientcert;
        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    public static String stringHash(String data) throws NoSuchAlgorithmException 
	{
		MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashInBytes = md.digest(data.getBytes(StandardCharsets.UTF_8));

        StringBuilder sb = new StringBuilder();
        for (byte b : hashInBytes) 
        {
            sb.append(String.format("%02x", b));
        }
        //System.out.println(sb.toString());
        return sb.toString();
    }

}
