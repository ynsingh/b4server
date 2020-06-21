package dao;
import java.io.BufferedReader;
import java.io.EOFException;
import java.io.FileReader;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

import server.properties_access;
import sun.misc.BASE64Decoder;

/*
Last modified by Maj Dushyant Choudhary Dated 20 April 2020 ; 1500 Hrs
This Class is used for Establishing Database Connectivity and Performing Database Operations
*/

public class DatabaseConnection 
{	
    /*
    toDb() method is called to insert auto-generated otp into the otp table.
    Insert query is executed to insert otp,emailid and client certificate to otp table
    */
    public static void toDb(String otp, String emailid, String ccert) throws ClassNotFoundException, SQLException  
        {
		// TODO Auto-generated method stub
		
		try
	    {
	      // create a mysql database connection
	      //String myDriver = properties_access.read_property("server.properties", "database_driver");
	      //String myUrl = properties_access.read_property("server.properties", "database_url");
	      //Class.forName(myDriver);
	      Connection conn = connect_database();
	      
	      Statement st = conn.createStatement();

	      // note that i'm leaving "date_created" out of this insert statement
	      String Query="INSERT INTO otp  (otp, emailid, ccert) VALUES ( '" + otp + "','" + emailid + "','" + ccert + "')" ;
	      System.out.println("The query goes to db "+Query);
	      st.executeUpdate("INSERT INTO otp  (otp, emailid, ccert) VALUES ( '" + otp + "','" + emailid + "','" + ccert + "')") ;

	      conn.close();
	    }
	    catch (Exception e)
	    {
	      System.err.println("Got an exception to db!");
	      System.err.println(e.getMessage());
              Connection conn = connect_database();
              PreparedStatement st = conn.prepareStatement(" UPDATE otp SET otp=? WHERE emailid=?");
              st.setString(1, otp);
              st.setString(2, emailid); 
              st.executeUpdate() ;
              conn.close();

	    }
	}
    /*
    fromDb() method is called to extract auto-generated otp stored in the otp table.
    Select query is executed to extract otp corresponding to emailid from otp table
    */
	public static String fromDb(String emailid) throws ClassNotFoundException, SQLException  {
		// TODO Auto-generated method stub
			String OtpFromDb = null;
			try
		    {
		      // create a mysql database connection
		      //String myDriver = "com.mysql.jdbc.Driver";
		      //String myUrl = "jdbc:mysql://localhost:3306/sys?autoReconnect=true&useSSL=false";
		      //Class.forName(myDriver);
		      //Connection conn = DriverManager.getConnection(myUrl, "root", "ic64276x");
				Connection conn = connect_database();
		      Statement st = conn.createStatement();


		      // to store otp to database
		      //System.out.println(sql);
		      ResultSet rs = st.executeQuery("SELECT otp FROM otp where emailid = '" + emailid + "'");
		      while(rs.next())	      
		      {
		    	  OtpFromDb=rs.getString("otp");
		    	  //System.out.println(OtpFromDb);
		    	  //conn.close();
		    	  
		      } 
		      conn.close(); 
		      
		      
		    }
		      catch (Exception e)
			    {
			      System.err.println("Got an exception from db!");
			      System.err.println(e.getMessage());
			    }
				return OtpFromDb;
		    }
        /*
    toKeyStoreOTP() method is called to update otp in the otp table.
    Update query is executed to update otp corresponding to emailid in otp table
    */
                public static void toKeystoreOTP(String otp, String emailid, String ccert) throws ClassNotFoundException, SQLException  {
		// TODO Auto-generated method stub
		
		try
                {
	      Connection conn = connect_database();
	      
	      PreparedStatement st = conn.prepareStatement(" UPDATE otp SET otp=? WHERE emailid=?");
              st.setString(1, otp);
              st.setString(2, emailid);
	      st.executeUpdate() ;

	      conn.close();
	    }
	    catch (Exception e)
	    {
	      System.err.println("Got an exception keystore otp!");
	      System.err.println(e.getMessage());
	    }
	}
                /*
    CertfromDb() method is called to extract certificate from the otp table.
    Select query is executed to extract certificate corresponding to emailid from otp table
    */
		public static String CertfromDb(String emailid) throws ClassNotFoundException, SQLException  {
			// TODO Auto-generated method stub
				String CertFromDb = null;
				try
			    {
			      // create a mysql database connection
			     /* String myDriver = "com.mysql.jdbc.Driver";
			      String myUrl = "jdbc:mysql://localhost:3306/sys?autoReconnect=true&useSSL=false";
			      Class.forName(myDriver);
			      Connection conn = DriverManager.getConnection(myUrl, "root", "ic64276x");
			     */
					Connection conn = connect_database();
			      Statement st = conn.createStatement();


			      // to store otp to database


			     // String sql;
			     // sql = "SELECT otp FROM otp where emailid = \" vijit@iitk.ac.in \" ";
			      //System.out.println(sql);
			      ResultSet rs = st.executeQuery("SELECT ccert FROM otp where emailid = '" + emailid + "'");
			      while(rs.next())	      
			      {
			    	  CertFromDb=rs.getString("ccert");
			    	  //System.out.println(OtpFromDb);
			    	  //conn.close();
			    	  
			      } 
			      conn.close(); 
			      
			      
			    }
			      catch (Exception e)
				    {
				      System.err.println("Got an exception cert from db!");
				      System.err.println(e.getMessage());
				    }
					return CertFromDb;
			    }
                /*
    keytoDb() method is called to insert keystore details into the keystore table.
    Keystore query is executed to insert nodeid,emailid,private key,public key,validity,Organisational Unit,Organisation,City,State,Country,Alias,Password into keystore table
    */
		public static void keytoDb(String nodeid, String emailid, PublicKey pubkey,  long validity, String OrganisationalUnit, String Organisation, String City, String State, String Country, String DeviceID) throws ClassNotFoundException, SQLException  {
			// TODO Auto-generated method stub
			
			try
		    {
		      // create a mysql database connection
		      /*String myDriver = "com.mysql.jdbc.Driver";
		      String myUrl = "jdbc:mysql://localhost:3306/sys?autoReconnect=true&useSSL=false";
		      Class.forName(myDriver);
		      Connection conn = DriverManager.getConnection(myUrl, "root", "ic64276x");
		      */
				Connection conn = connect_database();
		      Statement st = conn.createStatement();

		      // note that i'm leaving "date_created" out of this insert statement
		      st.executeUpdate("INSERT INTO keystore VALUES ( '" + nodeid +"','" + emailid + "','" + pubkey +"','" +  validity + "','" + OrganisationalUnit +"','"+ Organisation + "','" + City + "','" + State +"','"+ Country + "','" + DeviceID + "')" ) ;

		      conn.close();
		    }
		    catch (Exception e)
		    {
		      System.err.println("Got an exception key to db!");
		      System.err.println(e.getMessage());
		    }
		}
      /*
    keystoretoDb() method is called to insert keystore recovery details into keystore_recovery table.
    Insert query is executed to insert emailid,server certifictar and client certificate to keystore_recovery table
    */          
                public static void keystoretoDb(String emailid, String servercert, String clientcert,String device_id,String node_id,String kr_date,String lr_date) throws ClassNotFoundException, SQLException  
                {
			// TODO Auto-generated method stub
			
			try
                        {
		      // create a mysql database connection
		      /*String myDriver = "com.mysql.jdbc.Driver";
		      String myUrl = "jdbc:mysql://localhost:3306/sys?autoReconnect=true&useSSL=false";
		      Class.forName(myDriver);
		      Connection conn = DriverManager.getConnection(myUrl, "root", "ic64276x");
		      */
				Connection conn = connect_database();
		      Statement st = conn.createStatement();

		      // note that i'm leaving "date_created" out of this insert statement
		      st.executeUpdate("INSERT INTO keystore_recovery(emailid,servercertificate,clientcertificate,keystore,device_id,node_id,kr_date,last_recovery_date) VALUES ( '" + emailid +"','" +servercert + "','" + clientcert +"','" + null +"','"+device_id+ "','" +node_id+ "','" +kr_date+ "','" +null+"')" ) ;

		      conn.close();
		    }
		    catch (Exception e)
		    {
		      System.err.println("Got an exception keystore to db!");
		      System.out.println(e.getMessage());
                      e.printStackTrace();
		    }
		}
                /*
    keystorefromDb() method is called to extract keystore recovery details from keystore_recovery table.
    Select query is executed to extract server certificate and client certificate corresponding to emailid from keystore_recovery table
    */
                public static String keystorefromDb(String emailid) throws ClassNotFoundException, SQLException  {
			// TODO Auto-generated method stub
				String servercertificate = null;
                                String clientcertificate = null;    
                                try
			    {
			      
			      Connection conn = connect_database();
			      Statement st = conn.createStatement();

			      ResultSet rs = st.executeQuery("SELECT * FROM keystore_recovery where emailid = '" + emailid + "'");
			      while(rs.next())	      
			      {
			    	  servercertificate=rs.getString("servercertificate");
                                  clientcertificate=rs.getString("clientcertificate");
			    	  //System.out.println(OtpFromDb);
			    	  //conn.close();
			    	  
			      } 
			      conn.close();   
			    }
			      catch (Exception e)
				    {
				      System.err.println("Got an exception keystore from db!");
				      System.err.println(e.getMessage());
				    }
					return servercertificate+":::::::"+clientcertificate;
			    }
                public static boolean check_keystore(String emailid)
                {
                    boolean flag=false;
                    try
                    {
			Connection conn = connect_database();
			Statement st = conn.createStatement();
                        
			ResultSet rs = st.executeQuery("SELECT * FROM keystore_recovery where emailid = '" + emailid + "'");
			while(rs.next())	      
			{
			    flag=true;	  
			} 
			      conn.close(); 
                    }
                    catch (Exception e)
                    {
                        System.err.println("Got an exception check key store!");
                        System.err.println(e.getMessage());
                    }
                    return flag;
                }
                /*
    keystoredelete() method is called to delete keystore recovery entry in keystore_recovery table.
    Delete query is executed to delete server certificate and client certificate corresponding to emailid in keystore_recovery table
    */
                
                public static void keystoredelete(String emailid) throws ClassNotFoundException, SQLException{
			// TODO Auto-generated method stub
			
			try
		    {
		      // create a mysql database connection
		      /*String myDriver = "com.mysql.jdbc.Driver";
		      String myUrl = "jdbc:mysql://localhost:3306/sys?autoReconnect=true&useSSL=false";
		      Class.forName(myDriver);
		      Connection conn = DriverManager.getConnection(myUrl, "root", "ic64276x");
		      */
				Connection conn = connect_database();
		      Statement st = conn.createStatement();

		      // note that i'm leaving "date_created" out of this insert statement
		      st.executeUpdate("DELETE FROM keystore_recovery WHERE emailid='" + emailid+"'");
                      //st.executeUpdate("DELETE FROM otp WHERE emailid='" + emailid+"'");

		      conn.close();
		    }
		    catch (Exception e)
		    {
		      System.err.println("Got an exception keystore delete!");
		      System.err.println(e.getMessage());
		    }
		}
                
                public static void lrdatetoDb(String emailid, String date) throws ClassNotFoundException, SQLException  
                {
			// TODO Auto-generated method stub
			
			try
                        {
		      // create a mysql database connection
		      /*String myDriver = "com.mysql.jdbc.Driver";
		      String myUrl = "jdbc:mysql://localhost:3306/sys?autoReconnect=true&useSSL=false";
		      Class.forName(myDriver);
		      Connection conn = DriverManager.getConnection(myUrl, "root", "ic64276x");
		      */
				Connection conn = connect_database();
		      
                                PreparedStatement st = conn.prepareStatement(" UPDATE keystore_recovery SET last_recovery_date=? WHERE emailid=?");
                                st.setString(1, date);
                                st.setString(2, emailid);
                                st.executeUpdate() ;
                                
		      conn.close();
		    }
		    catch (Exception e)
		    {
		      System.err.println("Got an exception lr date to db!");
		      System.err.println(e.getMessage());
		    }
		}
                /*
    jkstoDb() method is called to insert jks into the keystore_recovery table.
    Update query is executed to insert jks corresponding to emailid in keystore_recovery table
    */
                public static void jkstoDb(String emailid, String jks) throws ClassNotFoundException, SQLException  
                {
			// TODO Auto-generated method stub
			
			try
                        {
		      // create a mysql database connection
		      /*String myDriver = "com.mysql.jdbc.Driver";
		      String myUrl = "jdbc:mysql://localhost:3306/sys?autoReconnect=true&useSSL=false";
		      Class.forName(myDriver);
		      Connection conn = DriverManager.getConnection(myUrl, "root", "ic64276x");
		      */
				Connection conn = connect_database();
		      
                                PreparedStatement st = conn.prepareStatement(" UPDATE keystore_recovery SET keystore=? WHERE emailid=?");
                                st.setString(1, jks);
                                st.setString(2, emailid);
                                st.executeUpdate() ;
                                
		      conn.close();
		    }
		    catch (Exception e)
		    {
		      System.err.println("Got an exception jks to db!");
		      System.err.println(e.getMessage());
		    }
		}
                /*
    jksfromDb() method is called to extract jks from keystore_recovery table.
    Select query is executed to extract jks corresponding to emailid from keystore_recovery table
    */
                
                public static String jksfromDb(String emailid) throws ClassNotFoundException, SQLException  {
			// TODO Auto-generated method stub
				String jks = null;
                                    
                                try
			    {
			      
			      Connection conn = connect_database();
			      Statement st = conn.createStatement();

			      ResultSet rs = st.executeQuery("SELECT * FROM keystore_recovery where emailid = '" + emailid + "'");
			      while(rs.next())	      
			      {
			    	  jks=rs.getString("keystore");
                                  //servercertificate=rs.getString("servercertificate");
                                  //clientcertificate=rs.getString("clientcertificate");
			    	  //System.out.println(OtpFromDb);
			    	  //conn.close();
			    	  
			      } 
			      conn.close(); 
			      
			      
			    }
			      catch (Exception e)
				    {
				      System.err.println("Got an exception jks from db!");
				      System.err.println(e.getMessage());
				    }
				    return jks;	
                                    //return servercertificate+":::::::"+clientcertificate;
			    }
                public static boolean check_crl(String certsrnum)
                {
                    boolean flag=false;
                    try
                    {
			Connection conn = connect_database();
			Statement st = conn.createStatement();
                        
			ResultSet rs = st.executeQuery("SELECT * FROM crl where certificate_srno = '" + certsrnum + "'");
			while(rs.next())	      
			{
			    flag=true;	  
			} 
			      conn.close(); 
                    }
                    catch (Exception e)
                    {
                        System.err.println("Got an exception check crl!");
                        System.err.println(e.getMessage());
                    }
                    return flag;
                }
                /*
    crltoDb() method is called to insert crl entry into the crl table.
    Insert query is executed to insert emailid,certificate,reason,expiry date and revocation date to crl table
    */
                public static void crltoDb(String emailid, String cert, String reason,String exp_date,String revocation_date,String cert_srno) throws ClassNotFoundException, SQLException  
                {
			// TODO Auto-generated method stub
			
			try
                        {
		      // create a mysql database connection
		      /*String myDriver = "com.mysql.jdbc.Driver";
		      String myUrl = "jdbc:mysql://localhost:3306/sys?autoReconnect=true&useSSL=false";
		      Class.forName(myDriver);
		      Connection conn = DriverManager.getConnection(myUrl, "root", "ic64276x");
		      */
				Connection conn = connect_database();
		      Statement st = conn.createStatement();

		      // note that i'm leaving "date_created" out of this insert statement
                      String query="INSERT INTO crl(email,certificate,reason,expiry_date,revocation_date,certificate_srno) VALUES ('" + emailid +"','" +cert + "','" + reason +"','" + exp_date +"','" + revocation_date +"','"+cert_srno+"')";
		      System.out.println(query);
                      st.executeUpdate(query);

		      conn.close();
		    }
		    catch (Exception e)
		    {
                        System.err.println("Got an exception crl to db!");
                        System.err.println(e.getMessage());
		    //  System.out.println(e.printStackTrace());
		    }
		}
                /*
    crlverifyEmail() method is called to verify passed email with email present in crl table.
    Select query is executed to extract emailid corresponding to the given emailid in crl table.
    If emailid is present return true else return false 
    */
                public static boolean crlverifyEmail(String emailid) throws ClassNotFoundException, SQLException  
                {
			// TODO Auto-generated method stub
				String email = null;
                                boolean flag=false;    
                                try
			    {
			      
			      Connection conn = connect_database();
			      Statement st = conn.createStatement();

			      ResultSet rs = st.executeQuery("SELECT * FROM crl where email = '" + emailid + "'");
			      while(rs.next())	      
			      {
			    	 //email=rs.getString("jks");
                                 flag=true;
                                  //servercertificate=rs.getString("servercertificate");
                                  //clientcertificate=rs.getString("clientcertificate");
			    	  //System.out.println(OtpFromDb);
			    	  //conn.close();
			      } 
			      conn.close(); 
			      			      
			    }
			      catch (Exception e)
				    {
				      System.err.println("Got an exception crl verify email!");
				      System.err.println(e.getMessage());
				    }
				    return flag;	
                                    //return servercertificate+":::::::"+clientcertificate;
			    }
                /*
    crlUpdateCertificate() method is called to update crl entry into the crl table.
    Update query is executed to update certificate,expiry date and revocation date corresponding to emailid in crl table
    */
                public static void crlUpdateCertificate(String emailid, String ccert,String exp,String dat,String hash) throws ClassNotFoundException, SQLException  
                {
		// TODO Auto-generated method stub
		
		try
                {
	      Connection conn = connect_database();
	      
	      PreparedStatement st = conn.prepareStatement(" UPDATE crl SET certificate=?,expiry_date=?,revocation_date=?,certificate_srno=? WHERE email=?");
              st.setString(1, ccert);
              st.setString(2, exp);
              st.setString(3, dat);
              st.setString(4, hash);
              st.setString(5, emailid);
              st.executeUpdate() ;

	      conn.close();
	    }
	    catch (Exception e)
	    {
	      System.err.println("Got an exception crl update cert!");
	      System.err.println(e.getMessage());
	    }
	}
		/*
    PrivkeyfromDb() method is called to extract private key in keystore table.
    Select query is executed to extract private key corresponding to emailid from keystore table
    */
                public static PrivateKey PrivkeyfromDb(String emailid) throws ClassNotFoundException, SQLException, EOFException  {
			// TODO Auto-generated method stub
				String privkeyFromDb ;
				PrivateKey priv = null;
				try
			    {
			      // create a mysql database connection
			     /* String myDriver = "com.mysql.jdbc.Driver";
			      String myUrl = "jdbc:mysql://localhost:3306/sys?autoReconnect=true&useSSL=false";
			      Class.forName(myDriver);
			      Connection conn = DriverManager.getConnection(myUrl, "root", "ic64276x");
			     */
					Connection conn = connect_database();
			      Statement st = conn.createStatement();


			      // to store otp to database


			     // String sql;
			     // sql = "SELECT otp FROM otp where emailid = \" vijit@iitk.ac.in \" ";
			      //System.out.println(sql);
			      ResultSet rs = st.executeQuery("SELECT privkey FROM keystore where emailid = '" + emailid + "'");
			      while(rs.next())	      
			      {
			    	  privkeyFromDb=rs.getString("privkey");
                                  System.out.println("privkeyFromDb" + privkeyFromDb);
			    	  //ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
			    	  //buffer.putLong(privkeyFromDb);
			    	  byte[] keybytes = Base64.getDecoder().decode(privkeyFromDb);
			    	 // int i = keybytes.length;
			    	  //System.out.println("byte length" + i);
			    	 // for (int j=0;j<i;j++)
			    	  //{System.out.println("byte data" + keybytes[j]);
			    	  
			    	  //}
			    	  //System.out.println("a1");
			    	  PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keybytes);
			    	 // System.out.println("a2");
			    	  KeyFactory fact = KeyFactory.getInstance("RSA");
			    	 // System.out.println("a3");
			    	  priv = fact.generatePrivate(keySpec);
			    	 // System.out.println("privkey data" + getHexString(priv.getEncoded()));
			    	  //Arrays.fill(clear, (byte) 0);
			    	    //return priv;
			    	 /* KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			    	  EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privkeyFromDb);
			    	  System.out.println("encodekeyspec = " + privateKeySpec);
			    	  privkey = keyFactory.generatePrivate(privateKeySpec);
			    	  System.out.println("privkey = " + privkey);*/
			    	  //System.out.println(OtpFromDb);
			    	  //conn.close();
			    	  
			      } 
			      conn.close(); 
			      
			      
			    }
			      catch (Exception e)
				    {
				      System.err.println("Got an exception in database priv key from db");
				      e.printStackTrace(System.out);
				      System.err.println("M "+ e.getMessage());
				    }
					return priv;
			    }
                public static PrivateKey PrivkeyfromFile(String path) throws ClassNotFoundException, SQLException, EOFException  {
			// TODO Auto-generated method stub
				String privkeyFromFile = null ;
				PrivateKey priv = null;
				try
			    {     //String p=Paths.get("").toAbsolutePath().toString()+"\\key.txt";
                                String p= path;  
                                BufferedReader br = new BufferedReader(new FileReader(p)); 
                                  String st;
                                  while ((st = br.readLine()) != null)
                                  {
                                      privkeyFromFile=st;
                                  }
			          
                                  System.out.println("privkeyFromDb" + privkeyFromFile);
			    	  //ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
			    	  //buffer.putLong(privkeyFromDb);
			    	  byte[] keybytes = Base64.getDecoder().decode(privkeyFromFile);
			    	 // int i = keybytes.length;
			    	  //System.out.println("byte length" + i);
			    	 // for (int j=0;j<i;j++)
			    	  //{System.out.println("byte data" + keybytes[j]);
			    	  
			    	  //}
			    	  //System.out.println("a1");
			    	  PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keybytes);
			    	 // System.out.println("a2");
			    	  KeyFactory fact = KeyFactory.getInstance("RSA");
			    	 // System.out.println("a3");
			    	  priv = fact.generatePrivate(keySpec);
			    	 // System.out.println("privkey data" + getHexString(priv.getEncoded()));
			    	  //Arrays.fill(clear, (byte) 0);
			    	    //return priv;
			    	 /* KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			    	  EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privkeyFromDb);
			    	  System.out.println("encodekeyspec = " + privateKeySpec);
			    	  privkey = keyFactory.generatePrivate(privateKeySpec);
			    	  System.out.println("privkey = " + privkey);*/
			    	  //System.out.println(OtpFromDb);
			    	  //conn.close();
			  
			    }
			      catch (Exception e)
				    {
				      System.err.println("Got an exception in file priv key from file");
				      e.printStackTrace(System.out);
				      System.err.println("M "+ e.getMessage());
				    }
					return priv;
			    }
                
                public static void multideviceEntry(String emailid,String device_id) throws ClassNotFoundException, SQLException  
                {
			// TODO Auto-generated method stub
			
			try
                        {
		      // create a mysql database connection
		      /*String myDriver = "com.mysql.jdbc.Driver";
		      String myUrl = "jdbc:mysql://localhost:3306/sys?autoReconnect=true&useSSL=false";
		      Class.forName(myDriver);
		      Connection conn = DriverManager.getConnection(myUrl, "root", "ic64276x");
		      */
				Connection conn = connect_database();
		      Statement st = conn.createStatement();

		      // note that i'm leaving "date_created" out of this insert statement
		      st.executeUpdate("INSERT INTO multidevice(emailid,deviceid,devicenodeid,lastaccessdate,keystoretransferdate) VALUES ( '" + emailid +"','" +device_id + "','" + device_id +"','" + new SimpleDateFormat("dd-MM-yyyy").format(new Date()) +"','"+new SimpleDateFormat("dd-MM-yyyy").format(new Date())+"')" ) ;

		      conn.close();
		    }
		    catch (Exception e)
		    {
		      System.err.println("Got an exception multi device entry!");
		      System.out.println(e.getMessage());
                      e.printStackTrace();
		    }
		}
                
		private static String getHexString(byte[] b) {
			String result = "";
			for (int i = 0; i < b.length; i++) {
				result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
			}
			return result;
		}
                
		private static Connection connect_database() {
		      String propfile= "server.properties";
                      System.out.println(propfile);
		      //String myDriver = properties_access.read_property(propfile, "database_driver");
		      //String myUrl = properties_access.read_property(propfile, "database_url");
		      String myDriver="com.mysql.jdbc.Driver";
                      String myUrl="jdbc:mysql://localhost:3306/b4server?autoReconnect=true&useSSL=false&useUnicode=true&useJDBCCompliantTimezoneShift=true&useLegacyDatetimeCode=false&serverTimezone=UTC";
                      
                      try 
		      {
				Class.forName(myDriver);
		      } 
		      catch (ClassNotFoundException e) 
		      {
				// TODO Auto-generated catch block
				e.printStackTrace();
		      }
		      Connection conn = null;
			try {
				//conn = DriverManager.getConnection(myUrl, properties_access.read_property(propfile, "database_user"), properties_access.read_property(propfile, "database_password"));
                            conn = DriverManager.getConnection(myUrl, "root","");
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		      return conn;
		}

}



