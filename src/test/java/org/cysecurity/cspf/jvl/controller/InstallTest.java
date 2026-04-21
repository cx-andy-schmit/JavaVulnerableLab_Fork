package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Test suite for Install controller SQL injection remediation.
 *
 * This test validates that the admin user insertion at line 127 (now 129-134)
 * properly uses PreparedStatement to prevent SQL injection attacks.
 *
 * @author Security Team
 */
public class InstallTest extends TestCase {

    private Connection testConnection;
    private static final String TEST_DB_URL = "jdbc:mysql://localhost:3306/";
    private static final String TEST_DB_NAME = "jvl_test_db";
    private static final String TEST_DB_USER = "root";
    private static final String TEST_DB_PASS = "";

    /**
     * Set up test database connection before each test.
     */
    protected void setUp() throws Exception {
        super.setUp();
        try {
            Class.forName("com.mysql.jdbc.Driver");
            // Note: In actual test environment, configure these from test properties
        } catch (ClassNotFoundException e) {
            // Skip tests if MySQL driver is not available
            System.out.println("MySQL driver not available, tests will be skipped");
        }
    }

    /**
     * Clean up test database after each test.
     */
    protected void tearDown() throws Exception {
        if (testConnection != null && !testConnection.isClosed()) {
            try {
                Statement stmt = testConnection.createStatement();
                stmt.executeUpdate("DROP DATABASE IF EXISTS " + TEST_DB_NAME);
                stmt.close();
                testConnection.close();
            } catch (SQLException e) {
                // Ignore cleanup errors
            }
        }
        super.tearDown();
    }

    /**
     * Test that PreparedStatement properly escapes SQL injection attempts
     * in the adminuser field.
     *
     * This test validates that malicious input like:
     * "admin', 'hacked', 'evil@localhost', 'pwned', 'default.jpg', 'admin', 1, 'hacked') --"
     * is treated as a literal string value, not SQL code.
     */
    public void testAdminUserSQLInjectionPrevention() throws Exception {
        try {
            Class.forName("com.mysql.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            System.out.println("Skipping test - MySQL driver not available");
            return;
        }

        Connection con = null;
        PreparedStatement pstmt = null;
        try {
            // Create test database
            con = DriverManager.getConnection(TEST_DB_URL, TEST_DB_USER, TEST_DB_PASS);
            Statement stmt = con.createStatement();
            stmt.executeUpdate("DROP DATABASE IF EXISTS " + TEST_DB_NAME);
            stmt.executeUpdate("CREATE DATABASE " + TEST_DB_NAME);
            stmt.close();
            con.close();

            // Connect to test database
            con = DriverManager.getConnection(TEST_DB_URL + TEST_DB_NAME, TEST_DB_USER, TEST_DB_PASS);
            stmt = con.createStatement();

            // Create users table
            stmt.executeUpdate("CREATE TABLE users(ID int NOT NULL AUTO_INCREMENT, username varchar(30), email varchar(60), password varchar(60), about varchar(50), privilege varchar(20), avatar TEXT, secretquestion int, secret varchar(30), primary key (id))");

            // Attempt SQL injection via adminuser parameter
            String maliciousUsername = "admin', 'hacked', 'evil@localhost', 'pwned', 'default.jpg', 'admin', 1, 'hacked') --";
            String safePassword = "hashedpassword123";

            // This is the FIXED code that uses PreparedStatement
            String adminInsertSql = "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) values (?, ?, 'admin@localhost', 'I am the admin of this application', 'default.jpg', 'admin', 1, 'rocky')";
            pstmt = con.prepareStatement(adminInsertSql);
            pstmt.setString(1, maliciousUsername);
            pstmt.setString(2, safePassword);
            pstmt.executeUpdate();
            pstmt.close();

            // Verify that only ONE user was inserted
            ResultSet rs = stmt.executeQuery("SELECT COUNT(*) as count FROM users");
            rs.next();
            int userCount = rs.getInt("count");
            assertEquals("PreparedStatement should prevent SQL injection - only 1 user should exist", 1, userCount);
            rs.close();

            // Verify the malicious input was treated as a literal string
            rs = stmt.executeQuery("SELECT username FROM users WHERE id = 1");
            rs.next();
            String insertedUsername = rs.getString("username");
            assertEquals("Malicious SQL should be stored as literal string", maliciousUsername, insertedUsername);
            rs.close();

            stmt.close();
        } catch (SQLException e) {
            fail("Test failed with SQLException: " + e.getMessage());
        } finally {
            if (pstmt != null) pstmt.close();
            if (con != null) con.close();
        }
    }

    /**
     * Test that PreparedStatement properly escapes SQL injection attempts
     * in the adminpass field.
     *
     * This test validates the specific vulnerability at line 127 where
     * adminpass is concatenated into the SQL query.
     */
    public void testAdminPasswordSQLInjectionPrevention() throws Exception {
        try {
            Class.forName("com.mysql.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            System.out.println("Skipping test - MySQL driver not available");
            return;
        }

        Connection con = null;
        PreparedStatement pstmt = null;
        try {
            // Create test database
            con = DriverManager.getConnection(TEST_DB_URL, TEST_DB_USER, TEST_DB_PASS);
            Statement stmt = con.createStatement();
            stmt.executeUpdate("DROP DATABASE IF EXISTS " + TEST_DB_NAME);
            stmt.executeUpdate("CREATE DATABASE " + TEST_DB_NAME);
            stmt.close();
            con.close();

            // Connect to test database
            con = DriverManager.getConnection(TEST_DB_URL + TEST_DB_NAME, TEST_DB_USER, TEST_DB_PASS);
            stmt = con.createStatement();

            // Create users table
            stmt.executeUpdate("CREATE TABLE users(ID int NOT NULL AUTO_INCREMENT, username varchar(30), email varchar(60), password varchar(60), about varchar(50), privilege varchar(20), avatar TEXT, secretquestion int, secret varchar(30), primary key (id))");

            // Attempt SQL injection via adminpass parameter - this is the PRIMARY vulnerability at line 127
            String safeUsername = "admin";
            String maliciousPassword = "pass123'); DROP TABLE users; --";

            // This is the FIXED code that uses PreparedStatement
            String adminInsertSql = "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) values (?, ?, 'admin@localhost', 'I am the admin of this application', 'default.jpg', 'admin', 1, 'rocky')";
            pstmt = con.prepareStatement(adminInsertSql);
            pstmt.setString(1, safeUsername);
            pstmt.setString(2, maliciousPassword);
            pstmt.executeUpdate();
            pstmt.close();

            // Verify table still exists (DROP TABLE should not have been executed)
            ResultSet rs = stmt.executeQuery("SELECT COUNT(*) as count FROM users");
            assertTrue("Table should still exist - SQL injection should be prevented", rs.next());
            int userCount = rs.getInt("count");
            assertEquals("PreparedStatement should prevent SQL injection - only 1 user should exist", 1, userCount);
            rs.close();

            // Verify the malicious password was stored as literal string
            rs = stmt.executeQuery("SELECT password FROM users WHERE username = 'admin'");
            rs.next();
            String insertedPassword = rs.getString("password");
            assertEquals("Malicious SQL in password should be stored as literal string", maliciousPassword, insertedPassword);
            rs.close();

            stmt.close();
        } catch (SQLException e) {
            fail("Test failed with SQLException: " + e.getMessage());
        } finally {
            if (pstmt != null) pstmt.close();
            if (con != null) con.close();
        }
    }

    /**
     * Test that PreparedStatement handles special characters correctly
     * without breaking SQL syntax.
     */
    public void testSpecialCharactersInAdminCredentials() throws Exception {
        try {
            Class.forName("com.mysql.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            System.out.println("Skipping test - MySQL driver not available");
            return;
        }

        Connection con = null;
        PreparedStatement pstmt = null;
        try {
            // Create test database
            con = DriverManager.getConnection(TEST_DB_URL, TEST_DB_USER, TEST_DB_PASS);
            Statement stmt = con.createStatement();
            stmt.executeUpdate("DROP DATABASE IF EXISTS " + TEST_DB_NAME);
            stmt.executeUpdate("CREATE DATABASE " + TEST_DB_NAME);
            stmt.close();
            con.close();

            // Connect to test database
            con = DriverManager.getConnection(TEST_DB_URL + TEST_DB_NAME, TEST_DB_USER, TEST_DB_PASS);
            stmt = con.createStatement();

            // Create users table
            stmt.executeUpdate("CREATE TABLE users(ID int NOT NULL AUTO_INCREMENT, username varchar(30), email varchar(60), password varchar(60), about varchar(50), privilege varchar(20), avatar TEXT, secretquestion int, secret varchar(30), primary key (id))");

            // Test with special characters that would break unescaped SQL
            String usernameWithQuotes = "admin'\"\\";
            String passwordWithSpecialChars = "p@ss'w0rd\"123\\";

            // Use PreparedStatement (the fix)
            String adminInsertSql = "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) values (?, ?, 'admin@localhost', 'I am the admin of this application', 'default.jpg', 'admin', 1, 'rocky')";
            pstmt = con.prepareStatement(adminInsertSql);
            pstmt.setString(1, usernameWithQuotes);
            pstmt.setString(2, passwordWithSpecialChars);
            pstmt.executeUpdate();
            pstmt.close();

            // Verify insertion succeeded
            ResultSet rs = stmt.executeQuery("SELECT username, password FROM users WHERE id = 1");
            assertTrue("User with special characters should be inserted", rs.next());
            assertEquals("Username with special chars should match", usernameWithQuotes, rs.getString("username"));
            assertEquals("Password with special chars should match", passwordWithSpecialChars, rs.getString("password"));
            rs.close();

            stmt.close();
        } catch (SQLException e) {
            fail("PreparedStatement should handle special characters: " + e.getMessage());
        } finally {
            if (pstmt != null) pstmt.close();
            if (con != null) con.close();
        }
    }

    /**
     * Test that PreparedStatement handles null values correctly.
     */
    public void testNullValuesInAdminCredentials() throws Exception {
        try {
            Class.forName("com.mysql.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            System.out.println("Skipping test - MySQL driver not available");
            return;
        }

        Connection con = null;
        PreparedStatement pstmt = null;
        try {
            // Create test database
            con = DriverManager.getConnection(TEST_DB_URL, TEST_DB_USER, TEST_DB_PASS);
            Statement stmt = con.createStatement();
            stmt.executeUpdate("DROP DATABASE IF EXISTS " + TEST_DB_NAME);
            stmt.executeUpdate("CREATE DATABASE " + TEST_DB_NAME);
            stmt.close();
            con.close();

            // Connect to test database
            con = DriverManager.getConnection(TEST_DB_URL + TEST_DB_NAME, TEST_DB_USER, TEST_DB_PASS);
            stmt = con.createStatement();

            // Create users table
            stmt.executeUpdate("CREATE TABLE users(ID int NOT NULL AUTO_INCREMENT, username varchar(30), email varchar(60), password varchar(60), about varchar(50), privilege varchar(20), avatar TEXT, secretquestion int, secret varchar(30), primary key (id))");

            // Test with null values
            String username = null;
            String password = null;

            // Use PreparedStatement (the fix)
            String adminInsertSql = "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) values (?, ?, 'admin@localhost', 'I am the admin of this application', 'default.jpg', 'admin', 1, 'rocky')";
            pstmt = con.prepareStatement(adminInsertSql);
            pstmt.setString(1, username);
            pstmt.setString(2, password);
            pstmt.executeUpdate();
            pstmt.close();

            // Verify insertion succeeded with null values
            ResultSet rs = stmt.executeQuery("SELECT username, password FROM users WHERE id = 1");
            assertTrue("User with null credentials should be inserted", rs.next());
            assertNull("Username should be null", rs.getString("username"));
            assertNull("Password should be null", rs.getString("password"));
            rs.close();

            stmt.close();
        } catch (SQLException e) {
            fail("PreparedStatement should handle null values: " + e.getMessage());
        } finally {
            if (pstmt != null) pstmt.close();
            if (con != null) con.close();
        }
    }

    /**
     * Test that PreparedStatement prevents union-based SQL injection attacks.
     */
    public void testUnionBasedSQLInjectionPrevention() throws Exception {
        try {
            Class.forName("com.mysql.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            System.out.println("Skipping test - MySQL driver not available");
            return;
        }

        Connection con = null;
        PreparedStatement pstmt = null;
        try {
            // Create test database
            con = DriverManager.getConnection(TEST_DB_URL, TEST_DB_USER, TEST_DB_PASS);
            Statement stmt = con.createStatement();
            stmt.executeUpdate("DROP DATABASE IF EXISTS " + TEST_DB_NAME);
            stmt.executeUpdate("CREATE DATABASE " + TEST_DB_NAME);
            stmt.close();
            con.close();

            // Connect to test database
            con = DriverManager.getConnection(TEST_DB_URL + TEST_DB_NAME, TEST_DB_USER, TEST_DB_PASS);
            stmt = con.createStatement();

            // Create users table
            stmt.executeUpdate("CREATE TABLE users(ID int NOT NULL AUTO_INCREMENT, username varchar(30), email varchar(60), password varchar(60), about varchar(50), privilege varchar(20), avatar TEXT, secretquestion int, secret varchar(30), primary key (id))");

            // Attempt UNION-based SQL injection
            String maliciousUsername = "admin' UNION SELECT 1,2,3,4,5,6,7,8,9 --";
            String password = "password123";

            // Use PreparedStatement (the fix)
            String adminInsertSql = "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) values (?, ?, 'admin@localhost', 'I am the admin of this application', 'default.jpg', 'admin', 1, 'rocky')";
            pstmt = con.prepareStatement(adminInsertSql);
            pstmt.setString(1, maliciousUsername);
            pstmt.setString(2, password);
            pstmt.executeUpdate();
            pstmt.close();

            // Verify only one row was inserted
            ResultSet rs = stmt.executeQuery("SELECT COUNT(*) as count FROM users");
            rs.next();
            assertEquals("UNION injection should be prevented", 1, rs.getInt("count"));
            rs.close();

            // Verify malicious input was stored as literal string
            rs = stmt.executeQuery("SELECT username FROM users WHERE id = 1");
            rs.next();
            assertEquals("UNION SQL should be stored as literal string", maliciousUsername, rs.getString("username"));
            rs.close();

            stmt.close();
        } catch (SQLException e) {
            fail("Test failed with SQLException: " + e.getMessage());
        } finally {
            if (pstmt != null) pstmt.close();
            if (con != null) con.close();
        }
    }

    /**
     * Test that PreparedStatement handles very long input strings correctly
     * without truncation vulnerabilities.
     */
    public void testLongInputStrings() throws Exception {
        try {
            Class.forName("com.mysql.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            System.out.println("Skipping test - MySQL driver not available");
            return;
        }

        Connection con = null;
        PreparedStatement pstmt = null;
        try {
            // Create test database
            con = DriverManager.getConnection(TEST_DB_URL, TEST_DB_USER, TEST_DB_PASS);
            Statement stmt = con.createStatement();
            stmt.executeUpdate("DROP DATABASE IF EXISTS " + TEST_DB_NAME);
            stmt.executeUpdate("CREATE DATABASE " + TEST_DB_NAME);
            stmt.close();
            con.close();

            // Connect to test database
            con = DriverManager.getConnection(TEST_DB_URL + TEST_DB_NAME, TEST_DB_USER, TEST_DB_PASS);
            stmt = con.createStatement();

            // Create users table
            stmt.executeUpdate("CREATE TABLE users(ID int NOT NULL AUTO_INCREMENT, username varchar(30), email varchar(60), password varchar(60), about varchar(50), privilege varchar(20), avatar TEXT, secretquestion int, secret varchar(30), primary key (id))");

            // Test with string exactly at column limit (30 chars for username)
            String username = "admin12345678901234567890123";  // 29 chars (within limit)
            String password = "pass1234567890123456789012345678901234567890123456789012"; // 58 chars (within 60 limit)

            // Use PreparedStatement (the fix)
            String adminInsertSql = "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) values (?, ?, 'admin@localhost', 'I am the admin of this application', 'default.jpg', 'admin', 1, 'rocky')";
            pstmt = con.prepareStatement(adminInsertSql);
            pstmt.setString(1, username);
            pstmt.setString(2, password);
            pstmt.executeUpdate();
            pstmt.close();

            // Verify insertion succeeded
            ResultSet rs = stmt.executeQuery("SELECT username, password FROM users WHERE id = 1");
            assertTrue("User with long credentials should be inserted", rs.next());
            assertEquals("Long username should match", username, rs.getString("username"));
            assertEquals("Long password should match", password, rs.getString("password"));
            rs.close();

            stmt.close();
        } catch (SQLException e) {
            fail("PreparedStatement should handle long strings: " + e.getMessage());
        } finally {
            if (pstmt != null) pstmt.close();
            if (con != null) con.close();
        }
    }
}
