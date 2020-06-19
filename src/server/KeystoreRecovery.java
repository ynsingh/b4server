package server;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignedObject;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import dao.DatabaseConnection;
import sun.misc.BASE64Encoder;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
Last modified by Maj Dushyant Choudhary Dated 22 March 2020 ; 1100 Hrs
This Servlet Class is the api for various keystore recovery tasks like :
    1.KeyStore OTP Gen,
    2.KeyStore OTP Verify
*/
@WebServlet("/KeystoreRecovery")
public class KeystoreRecovery extends HttpServlet 
{
    private static final long serialVersionUID = 1L;
    
    /**
     * @see HttpServlet#HttpServlet()
     */
    public KeystoreRecovery() 
    {
        super();
        // TODO Auto-generated constructor stub
    }

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
     */
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // TODO Auto-generated method stub
        response.getWriter().append("Served at: ").append(request.getContextPath());
    }

    /**
     * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
     */
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // TODO Auto-generated method stub
        System.out.println(" you are in do post method");
        
        String req=request.getParameter("req");
        String emailid=request.getParameter("emailid");
        
        if(req.equals("keystoreotpgen"))
        {
            System.out.println("keystoreotpgen SENDING EMAIL...");
            String Otp = SendMailTLS.sendEmail("otpsender247@gmail.com",emailid);
            //String Otp=String.valueOf(SendMailTLS.generateOTP(8));

            System.out.println("OTP SENT TO YOUR EMAIL ID PROVIDED IN CERTIFICATE.CHECK MAIL AND INPUT OTP FOR VERIFICATION");
            System.out.println("Sent Otp is "+ Otp);
            try {
                DatabaseConnection.toKeystoreOTP(Otp, emailid, null);
                PrintWriter out = response.getWriter();
                out.println("OTP SENT");
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SQLException ex) {
                Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
            }
            
        }
        else if(req.equals("keystoreotpverify"))
        {
            String certs;
        try {
            String otp=request.getParameter("otp");
            String SentOtp = DatabaseConnection.fromDb(emailid);
            String pattern = "yyyy-MM-dd";
                SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);

                String date = simpleDateFormat.format(new Date());
            if(otp.equals(SentOtp))
            {
                DatabaseConnection.lrdatetoDb(emailid, date);
                //certs=DatabaseConnection.jksfromDb(emailid);
            certs = DatabaseConnection.keystorefromDb(emailid);
            String cert[]=certs.split(":::::::");
            PrintWriter out = response.getWriter();
            out.println( cert[0]  +"ClientCert" + cert[1]);
            //    out.println(certs);
            }
            
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SQLException ex) {
            Logger.getLogger(KeystoreRecovery.class.getName()).log(Level.SEVERE, null, ex);
        }
        

        }
                            //doGet(request, response);
    }

}
