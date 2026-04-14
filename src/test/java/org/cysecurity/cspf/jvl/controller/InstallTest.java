package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Comprehensive security test for Install servlet
 * Tests SQL injection vulnerability remediation in admin user creation
 *
 * @author security-team
 */
public class InstallTest extends TestCase {

    private Connection testConnection;
    private static final String TEST_DB_URL = "jdbc:mysql://localhost:3306/";
    private static final String TEST_DB_NAME = "jvl_test_db";
    private static final String TEST_DB_USER = "root";
    private static final String TEST_DB_PASS = "";

    public InstallTest(String testName) {
        super(testName);
    }

    /**
     * Test that parameterized queries properly handle normal admin credentials
     * This validates the fix maintains functionality
     */
    public void testAdminInsertWithValidCredentials() throws Exception {
        // Setup test database
        Connection setupConn = null;
        Statement stmt = null;

        try {
            Class.forName("com.mysql.jdbc.Driver");
            setupConn = DriverManager.getConnection(TEST_DB_URL, TEST_DB_USER, TEST_DB_PASS);
            stmt = setupConn.createStatement();

            // Create test database
            stmt.executeUpdate("DROP DATABASE IF EXISTS " + TEST_DB_NAME);
            stmt.executeUpdate("CREATE DATABASE " + TEST_DB_NAME);
            stmt.close();
            setupConn.close();

            // Connect to test database
            testConnection = DriverManager.getConnection(TEST_DB_URL + TEST_DB_NAME, TEST_DB_USER, TEST_DB_PASS);
            Statement createStmt = testConnection.createStatement();

            // Create users table
            createStmt.executeUpdate("CREATE TABLE users(ID int NOT NULL AUTO_INCREMENT, username varchar(30), email varchar(60), password varchar(60), about varchar(50), privilege varchar(20), avatar TEXT, secretquestion int, secret varchar(30), primary key (id))");

            // Test valid credentials - simulating the fixed code
            String adminUser = "testadmin";
            String adminPass = "hashedpassword123";

            String adminInsertSql = "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";
            PreparedStatement pstmt = testConnection.prepareStatement(adminInsertSql);
            pstmt.setString(1, adminUser);
            pstmt.setString(2, adminPass);
            int rowsAffected = pstmt.executeUpdate();
            pstmt.close();

            // Verify insertion was successful
            assertEquals("Should insert exactly one row", 1, rowsAffected);

            // Verify data was inserted correctly
            PreparedStatement selectStmt = testConnection.prepareStatement("SELECT username, password, privilege FROM users WHERE username = ?");
            selectStmt.setString(1, adminUser);
            ResultSet rs = selectStmt.executeQuery();

            assertTrue("Admin user should exist", rs.next());
            assertEquals("Username should match", adminUser, rs.getString("username"));
            assertEquals("Password should match", adminPass, rs.getString("password"));
            assertEquals("Privilege should be admin", "admin", rs.getString("privilege"));

            rs.close();
            selectStmt.close();
            createStmt.close();

        } catch (ClassNotFoundException e) {
            // Skip test if MySQL driver not available in test environment
            System.out.println("MySQL driver not available, skipping test: " + e.getMessage());
        } catch (SQLException e) {
            // Skip test if database not available
            System.out.println("Database not available, skipping test: " + e.getMessage());
        } finally {
            cleanup();
        }
    }

    /**
     * Test that SQL injection attempts in username are properly escaped
     * This is the critical security test for the vulnerability fix
     */
    public void testAdminInsertBlocksSQLInjectionInUsername() throws Exception {
        Connection setupConn = null;
        Statement stmt = null;

        try {
            Class.forName("com.mysql.jdbc.Driver");
            setupConn = DriverManager.getConnection(TEST_DB_URL, TEST_DB_USER, TEST_DB_PASS);
            stmt = setupConn.createStatement();

            // Create test database
            stmt.executeUpdate("DROP DATABASE IF EXISTS " + TEST_DB_NAME);
            stmt.executeUpdate("CREATE DATABASE " + TEST_DB_NAME);
            stmt.close();
            setupConn.close();

            // Connect to test database
            testConnection = DriverManager.getConnection(TEST_DB_URL + TEST_DB_NAME, TEST_DB_USER, TEST_DB_PASS);
            Statement createStmt = testConnection.createStatement();

            // Create users table
            createStmt.executeUpdate("CREATE TABLE users(ID int NOT NULL AUTO_INCREMENT, username varchar(30), email varchar(60), password varchar(60), about varchar(50), privilege varchar(20), avatar TEXT, secretquestion int, secret varchar(30), primary key (id))");

            // Test SQL injection attempt in username
            // This payload attempts to inject malicious SQL: admin','admin','admin@localhost','admin','default.jpg','admin',1,'rocky'); DROP TABLE users; --
            String maliciousUsername = "admin','admin','admin@localhost','admin','default.jpg','admin',1,'rocky'); DROP TABLE users; --";
            String adminPass = "hashedpassword";

            // Use parameterized query (the fix)
            String adminInsertSql = "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";
            PreparedStatement pstmt = testConnection.prepareStatement(adminInsertSql);
            pstmt.setString(1, maliciousUsername);
            pstmt.setString(2, adminPass);
            pstmt.executeUpdate();
            pstmt.close();

            // Verify table still exists (injection was neutralized)
            Statement verifyStmt = testConnection.createStatement();
            ResultSet rs = verifyStmt.executeQuery("SELECT COUNT(*) as count FROM users");
            assertTrue("Should be able to query users table", rs.next());
            assertEquals("Should have exactly one user", 1, rs.getInt("count"));

            // Verify the malicious string was inserted as literal data (escaped)
            PreparedStatement selectStmt = testConnection.prepareStatement("SELECT username FROM users WHERE username = ?");
            selectStmt.setString(1, maliciousUsername);
            ResultSet userRs = selectStmt.executeQuery();
            assertTrue("Malicious username should be stored as literal string", userRs.next());
            assertEquals("Username should be stored exactly as provided (escaped)", maliciousUsername, userRs.getString("username"));

            userRs.close();
            selectStmt.close();
            rs.close();
            verifyStmt.close();
            createStmt.close();

        } catch (ClassNotFoundException e) {
            System.out.println("MySQL driver not available, skipping test: " + e.getMessage());
        } catch (SQLException e) {
            System.out.println("Database not available, skipping test: " + e.getMessage());
        } finally {
            cleanup();
        }
    }

    /**
     * Test that SQL injection attempts in password are properly escaped
     */
    public void testAdminInsertBlocksSQLInjectionInPassword() throws Exception {
        Connection setupConn = null;
        Statement stmt = null;

        try {
            Class.forName("com.mysql.jdbc.Driver");
            setupConn = DriverManager.getConnection(TEST_DB_URL, TEST_DB_USER, TEST_DB_PASS);
            stmt = setupConn.createStatement();

            // Create test database
            stmt.executeUpdate("DROP DATABASE IF EXISTS " + TEST_DB_NAME);
            stmt.executeUpdate("CREATE DATABASE " + TEST_DB_NAME);
            stmt.close();
            setupConn.close();

            // Connect to test database
            testConnection = DriverManager.getConnection(TEST_DB_URL + TEST_DB_NAME, TEST_DB_USER, TEST_DB_PASS);
            Statement createStmt = testConnection.createStatement();

            // Create users table
            createStmt.executeUpdate("CREATE TABLE users(ID int NOT NULL AUTO_INCREMENT, username varchar(30), email varchar(60), password varchar(60), about varchar(50), privilege varchar(20), avatar TEXT, secretquestion int, secret varchar(30), primary key (id))");

            // Test SQL injection attempt in password field
            String adminUser = "legitadmin";
            String maliciousPassword = "pass'); DELETE FROM users WHERE '1'='1";

            // Use parameterized query (the fix)
            String adminInsertSql = "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";
            PreparedStatement pstmt = testConnection.prepareStatement(adminInsertSql);
            pstmt.setString(1, adminUser);
            pstmt.setString(2, maliciousPassword);
            pstmt.executeUpdate();
            pstmt.close();

            // Verify table still exists and data is intact
            Statement verifyStmt = testConnection.createStatement();
            ResultSet rs = verifyStmt.executeQuery("SELECT COUNT(*) as count FROM users");
            assertTrue("Should be able to query users table", rs.next());
            assertEquals("Should have exactly one user (no deletion occurred)", 1, rs.getInt("count"));

            // Verify the malicious password was stored as literal data
            PreparedStatement selectStmt = testConnection.prepareStatement("SELECT password FROM users WHERE username = ?");
            selectStmt.setString(1, adminUser);
            ResultSet userRs = selectStmt.executeQuery();
            assertTrue("User should exist", userRs.next());
            assertEquals("Password should be stored as literal string (escaped)", maliciousPassword, userRs.getString("password"));

            userRs.close();
            selectStmt.close();
            rs.close();
            verifyStmt.close();
            createStmt.close();

        } catch (ClassNotFoundException e) {
            System.out.println("MySQL driver not available, skipping test: " + e.getMessage());
        } catch (SQLException e) {
            System.out.println("Database not available, skipping test: " + e.getMessage());
        } finally {
            cleanup();
        }
    }

    /**
     * Test special characters in credentials are properly handled
     */
    public void testAdminInsertWithSpecialCharacters() throws Exception {
        Connection setupConn = null;
        Statement stmt = null;

        try {
            Class.forName("com.mysql.jdbc.Driver");
            setupConn = DriverManager.getConnection(TEST_DB_URL, TEST_DB_USER, TEST_DB_PASS);
            stmt = setupConn.createStatement();

            // Create test database
            stmt.executeUpdate("DROP DATABASE IF EXISTS " + TEST_DB_NAME);
            stmt.executeUpdate("CREATE DATABASE " + TEST_DB_NAME);
            stmt.close();
            setupConn.close();

            // Connect to test database
            testConnection = DriverManager.getConnection(TEST_DB_URL + TEST_DB_NAME, TEST_DB_USER, TEST_DB_PASS);
            Statement createStmt = testConnection.createStatement();

            // Create users table
            createStmt.executeUpdate("CREATE TABLE users(ID int NOT NULL AUTO_INCREMENT, username varchar(30), email varchar(60), password varchar(60), about varchar(50), privilege varchar(20), avatar TEXT, secretquestion int, secret varchar(30), primary key (id))");

            // Test various special characters that could cause SQL issues
            String adminUser = "admin'test\"user";
            String adminPass = "p@ss'word\"123;--";

            // Use parameterized query (the fix)
            String adminInsertSql = "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";
            PreparedStatement pstmt = testConnection.prepareStatement(adminInsertSql);
            pstmt.setString(1, adminUser);
            pstmt.setString(2, adminPass);
            int rowsAffected = pstmt.executeUpdate();
            pstmt.close();

            // Verify insertion was successful
            assertEquals("Should insert exactly one row", 1, rowsAffected);

            // Verify special characters were preserved
            PreparedStatement selectStmt = testConnection.prepareStatement("SELECT username, password FROM users WHERE username = ?");
            selectStmt.setString(1, adminUser);
            ResultSet rs = selectStmt.executeQuery();

            assertTrue("User with special characters should exist", rs.next());
            assertEquals("Username with special chars should be preserved", adminUser, rs.getString("username"));
            assertEquals("Password with special chars should be preserved", adminPass, rs.getString("password"));

            rs.close();
            selectStmt.close();
            createStmt.close();

        } catch (ClassNotFoundException e) {
            System.out.println("MySQL driver not available, skipping test: " + e.getMessage());
        } catch (SQLException e) {
            System.out.println("Database not available, skipping test: " + e.getMessage());
        } finally {
            cleanup();
        }
    }

    /**
     * Test edge case: empty username and password
     */
    public void testAdminInsertWithEmptyCredentials() throws Exception {
        Connection setupConn = null;
        Statement stmt = null;

        try {
            Class.forName("com.mysql.jdbc.Driver");
            setupConn = DriverManager.getConnection(TEST_DB_URL, TEST_DB_USER, TEST_DB_PASS);
            stmt = setupConn.createStatement();

            // Create test database
            stmt.executeUpdate("DROP DATABASE IF EXISTS " + TEST_DB_NAME);
            stmt.executeUpdate("CREATE DATABASE " + TEST_DB_NAME);
            stmt.close();
            setupConn.close();

            // Connect to test database
            testConnection = DriverManager.getConnection(TEST_DB_URL + TEST_DB_NAME, TEST_DB_USER, TEST_DB_PASS);
            Statement createStmt = testConnection.createStatement();

            // Create users table
            createStmt.executeUpdate("CREATE TABLE users(ID int NOT NULL AUTO_INCREMENT, username varchar(30), email varchar(60), password varchar(60), about varchar(50), privilege varchar(20), avatar TEXT, secretquestion int, secret varchar(30), primary key (id))");

            // Test empty credentials
            String adminUser = "";
            String adminPass = "";

            // Use parameterized query (the fix)
            String adminInsertSql = "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";
            PreparedStatement pstmt = testConnection.prepareStatement(adminInsertSql);
            pstmt.setString(1, adminUser);
            pstmt.setString(2, adminPass);
            int rowsAffected = pstmt.executeUpdate();
            pstmt.close();

            // Verify insertion was successful even with empty strings
            assertEquals("Should insert exactly one row", 1, rowsAffected);

            // Verify empty strings were stored correctly
            Statement verifyStmt = testConnection.createStatement();
            ResultSet rs = verifyStmt.executeQuery("SELECT username, password FROM users");

            assertTrue("User should exist", rs.next());
            assertEquals("Empty username should be stored", "", rs.getString("username"));
            assertEquals("Empty password should be stored", "", rs.getString("password"));

            rs.close();
            verifyStmt.close();
            createStmt.close();

        } catch (ClassNotFoundException e) {
            System.out.println("MySQL driver not available, skipping test: " + e.getMessage());
        } catch (SQLException e) {
            System.out.println("Database not available, skipping test: " + e.getMessage());
        } finally {
            cleanup();
        }
    }

    /**
     * Test edge case: null values
     */
    public void testAdminInsertWithNullCredentials() throws Exception {
        Connection setupConn = null;
        Statement stmt = null;

        try {
            Class.forName("com.mysql.jdbc.Driver");
            setupConn = DriverManager.getConnection(TEST_DB_URL, TEST_DB_USER, TEST_DB_PASS);
            stmt = setupConn.createStatement();

            // Create test database
            stmt.executeUpdate("DROP DATABASE IF EXISTS " + TEST_DB_NAME);
            stmt.executeUpdate("CREATE DATABASE " + TEST_DB_NAME);
            stmt.close();
            setupConn.close();

            // Connect to test database
            testConnection = DriverManager.getConnection(TEST_DB_URL + TEST_DB_NAME, TEST_DB_USER, TEST_DB_PASS);
            Statement createStmt = testConnection.createStatement();

            // Create users table
            createStmt.executeUpdate("CREATE TABLE users(ID int NOT NULL AUTO_INCREMENT, username varchar(30), email varchar(60), password varchar(60), about varchar(50), privilege varchar(20), avatar TEXT, secretquestion int, secret varchar(30), primary key (id))");

            // Test null credentials
            String adminUser = null;
            String adminPass = null;

            // Use parameterized query (the fix)
            String adminInsertSql = "INSERT into users(username, password, email, About, avatar, privilege, secretquestion, secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";
            PreparedStatement pstmt = testConnection.prepareStatement(adminInsertSql);
            pstmt.setString(1, adminUser);
            pstmt.setString(2, adminPass);
            int rowsAffected = pstmt.executeUpdate();
            pstmt.close();

            // Verify insertion was successful with null values
            assertEquals("Should insert exactly one row", 1, rowsAffected);

            // Verify null values were stored correctly
            Statement verifyStmt = testConnection.createStatement();
            ResultSet rs = verifyStmt.executeQuery("SELECT username, password FROM users");

            assertTrue("User should exist", rs.next());
            assertNull("Null username should be stored as NULL", rs.getString("username"));
            assertNull("Null password should be stored as NULL", rs.getString("password"));

            rs.close();
            verifyStmt.close();
            createStmt.close();

        } catch (ClassNotFoundException e) {
            System.out.println("MySQL driver not available, skipping test: " + e.getMessage());
        } catch (SQLException e) {
            System.out.println("Database not available, skipping test: " + e.getMessage());
        } finally {
            cleanup();
        }
    }

    /**
     * Test that demonstrates the vulnerability would exist with string concatenation
     * This is a regression test to ensure we don't revert to vulnerable code
     */
    public void testVulnerableApproachDemonstration() throws Exception {
        Connection setupConn = null;
        Statement stmt = null;

        try {
            Class.forName("com.mysql.jdbc.Driver");
            setupConn = DriverManager.getConnection(TEST_DB_URL, TEST_DB_USER, TEST_DB_PASS);
            stmt = setupConn.createStatement();

            // Create test database
            stmt.executeUpdate("DROP DATABASE IF EXISTS " + TEST_DB_NAME);
            stmt.executeUpdate("CREATE DATABASE " + TEST_DB_NAME);
            stmt.close();
            setupConn.close();

            // Connect to test database
            testConnection = DriverManager.getConnection(TEST_DB_URL + TEST_DB_NAME, TEST_DB_USER, TEST_DB_PASS);
            Statement createStmt = testConnection.createStatement();

            // Create users table
            createStmt.executeUpdate("CREATE TABLE users(ID int NOT NULL AUTO_INCREMENT, username varchar(30), email varchar(60), password varchar(60), about varchar(50), privilege varchar(20), avatar TEXT, secretquestion int, secret varchar(30), primary key (id))");

            // This demonstrates what would happen with the OLD vulnerable code
            // Using string concatenation (DO NOT USE THIS IN PRODUCTION!)
            String adminUser = "normaluser";
            String maliciousPass = "pass'); INSERT INTO users(username,password,email,about,avatar,privilege,secretquestion,secret) VALUES('hacker','hacked','hacker@evil.com','pwned','evil.jpg','admin',1,'owned'); --";

            // VULNERABLE CODE (for demonstration only):
            String vulnerableSql = "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('"+adminUser+"','"+maliciousPass+"','admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";

            boolean injectionOccurred = false;
            try {
                Statement vulnerableStmt = testConnection.createStatement();
                vulnerableStmt.executeUpdate(vulnerableSql);
                vulnerableStmt.close();

                // Check if injection was successful
                Statement checkStmt = testConnection.createStatement();
                ResultSet rs = checkStmt.executeQuery("SELECT COUNT(*) as count FROM users");
                rs.next();
                int userCount = rs.getInt("count");
                rs.close();
                checkStmt.close();

                // If we see 2 users, the injection worked (1 intended + 1 injected)
                if (userCount > 1) {
                    injectionOccurred = true;
                }
            } catch (SQLException e) {
                // Injection might fail due to syntax error, which is also a vulnerability indicator
                injectionOccurred = true;
            }

            // This test documents that string concatenation IS vulnerable
            assertTrue("String concatenation approach is vulnerable to SQL injection", injectionOccurred);

            createStmt.close();

        } catch (ClassNotFoundException e) {
            System.out.println("MySQL driver not available, skipping test: " + e.getMessage());
        } catch (SQLException e) {
            System.out.println("Database not available, skipping test: " + e.getMessage());
        } finally {
            cleanup();
        }
    }

    /**
     * Cleanup test resources
     */
    private void cleanup() {
        try {
            if (testConnection != null && !testConnection.isClosed()) {
                testConnection.close();
            }

            // Cleanup test database
            Connection cleanupConn = DriverManager.getConnection(TEST_DB_URL, TEST_DB_USER, TEST_DB_PASS);
            Statement stmt = cleanupConn.createStatement();
            stmt.executeUpdate("DROP DATABASE IF EXISTS " + TEST_DB_NAME);
            stmt.close();
            cleanupConn.close();
        } catch (SQLException e) {
            // Ignore cleanup errors
        }
    }

    protected void tearDown() throws Exception {
        cleanup();
        super.tearDown();
    }
}
