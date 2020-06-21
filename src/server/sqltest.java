package server;

import dao.DatabaseConnection;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;

public class sqltest {

    public static void main(String[] args) throws ClassNotFoundException, SQLException, IOException  {
        // TODO Auto-generated method stub
        /*
        Class.forName("com.mysql.jdbc.Driver");
        Connection con=
            DriverManager.getConnection("jdbc:mysql://192.168.1.7:3306/jdbc_example","root","1234");
        System.out.println(con);

        Statement stmt=con.createStatement();
*/

// to store otp to database


        String OtpToDb, OtpFromDb;

        OtpToDb="111111";//Test OTP input
        String sql1;
        /*
        sql1= "insert into otp(otp) values('"+OtpToDb+"')";
        int rowsaffected=stmt.executeUpdate(sql1);
        System.out.println(rowsaffected);

        String sql;
        sql = "SELECT * FROM otp ORDER BY sno DESC LIMIT 0,1";
        ResultSet rs = stmt.executeQuery(sql);

        while(rs.next())
        {
            OtpFromDb=rs.getString(2);
            System.out.println(OtpFromDb);
        }
        con.close();
        */
        
        String ServerCertbyte = DatabaseConnection.CertfromDb("b4server@iitk.ac.in");
        X509Certificate[] servercert =	ConvertStringCertToX509.convertToX509Certarray(ServerCertbyte);
        System.out.println(servercert[0].getSigAlgName());
    }
}

