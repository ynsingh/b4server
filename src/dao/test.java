package dao;

import java.sql.Connection;
import java.sql.DriverManager;


import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import server.GenerateCertificate;


public class test {

	
	
	public static void main(String[] args) throws ClassNotFoundException, SQLException {
		
		
Class.forName("com.mysql.jdbc.Driver");
Connection con= DriverManager.getConnection("jdbc:mysql://localhost:3306/b4server_master","root","");
System.out.println(con);

            try {
                //GenerateCertificate.createSelfSignedCert();
                DatabaseConnection.PrivkeyfromFile(null);
            } catch (Exception ex) {
                Logger.getLogger(test.class.getName()).log(Level.SEVERE, null, ex);
            }
	}}