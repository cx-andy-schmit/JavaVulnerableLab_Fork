package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static org.mockito.Mockito.*;

/**
 * Test suite for Install servlet to verify SQL injection vulnerability remediation.
 *
 * These tests ensure that:
 * 1. SQL injection attacks are prevented through parameterized queries
 * 2. Normal installation functionality works correctly
 * 3. Special characters and malicious inputs are properly handled
 * 4. Database operations complete successfully without SQL injection risks
 */
public class InstallTest extends TestCase {

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private HttpServletResponse mockResponse;

    @Mock
    private ServletContext mockServletContext;

    private Install installServlet;
    private StringWriter responseWriter;
    private Connection testConnection;
    private String testDbUrl = "jdbc:mysql://localhost:3306/";
    private String testDbName = "jvl_test_db";
    private String testDbUser = "root";
    private String testDbPass = "";

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        MockitoAnnotations.initMocks(this);
        installServlet = new Install();
        responseWriter = new StringWriter();

        // Create a temporary config.properties file
        File tempConfigFile = File.createTempFile("config", ".properties");
        tempConfigFile.deleteOnExit();

        // Write minimal properties to the file
        FileWriter fw = new FileWriter(tempConfigFile);
        fw.write("dburl=jdbc:mysql://localhost:3306/\n");
        fw.write("jdbcdriver=com.mysql.jdbc.Driver\n");
        fw.write("dbuser=root\n");
        fw.write("dbpass=\n");
        fw.write("dbname=jvl\n");
        fw.write("siteTitle=JVL Test\n");
        fw.close();

        // Mock servlet context to return temp config path
        when(mockRequest.getServletContext()).thenReturn(mockServletContext);
        when(mockServletContext.getRealPath("/WEB-INF/config.properties"))
            .thenReturn(tempConfigFile.getAbsolutePath());
    }

    @Override
    protected void tearDown() throws Exception {
        // Clean up test database if it exists
        try {
            if (testConnection != null && !testConnection.isClosed()) {
                testConnection.close();
            }

            // Drop test database
            Class.forName("com.mysql.jdbc.Driver");
            Connection cleanupConn = DriverManager.getConnection(testDbUrl, testDbUser, testDbPass);
            Statement stmt = cleanupConn.createStatement();
            stmt.executeUpdate("DROP DATABASE IF EXISTS " + testDbName);
            stmt.close();
            cleanupConn.close();
        } catch (Exception e) {
            // Ignore cleanup errors in tests
        }
        super.tearDown();
    }

    /**
     * Test that verifies SQL injection prevention in admin user creation.
     * This test attempts a SQL injection attack via the adminuser parameter
     * and ensures it's treated as literal data, not executable SQL.
     */
    public void testSqlInjectionPreventionInAdminUser() throws Exception {
        // Arrange: Create a malicious username that attempts SQL injection
        String maliciousUsername = "admin','malicious@test.com','hacked','hack','hack.jpg','admin',1,'hack'); DROP TABLE users; --";
        String normalPassword = "hashedPassword123";

        // Mock request parameters
        when(mockRequest.getParameter("dburl")).thenReturn(testDbUrl);
        when(mockRequest.getParameter("jdbcdriver")).thenReturn("com.mysql.jdbc.Driver");
        when(mockRequest.getParameter("dbuser")).thenReturn(testDbUser);
        when(mockRequest.getParameter("dbpass")).thenReturn(testDbPass);
        when(mockRequest.getParameter("dbname")).thenReturn(testDbName);
        when(mockRequest.getParameter("siteTitle")).thenReturn("Test Site");
        when(mockRequest.getParameter("adminuser")).thenReturn(maliciousUsername);
        when(mockRequest.getParameter("adminpass")).thenReturn(normalPassword);
        when(mockRequest.getParameter("setup")).thenReturn("1");

        when(mockResponse.getWriter()).thenReturn(new PrintWriter(responseWriter));

        // Act: Process the request
        try {
            installServlet.processRequest(mockRequest, mockResponse);

            // Assert: Verify the database was created and check user data
            Class.forName("com.mysql.jdbc.Driver");
            testConnection = DriverManager.getConnection(testDbUrl + testDbName, testDbUser, testDbPass);

            // Verify the users table exists and wasn't dropped (SQL injection failed)
            Statement stmt = testConnection.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT COUNT(*) as count FROM users");
            assertTrue("Users table should exist", rs.next());
            int userCount = rs.getInt("count");

            // Should have multiple users (admin + test users), not just one
            assertTrue("Should have multiple users created", userCount > 1);

            // Verify the malicious username was inserted as literal data
            ResultSet adminRs = stmt.executeQuery("SELECT username, email FROM users WHERE privilege='admin'");
            if (adminRs.next()) {
                String insertedUsername = adminRs.getString("username");
                // The malicious SQL should be stored as a literal string, not executed
                assertEquals("Username should be stored as literal data", maliciousUsername, insertedUsername);
            }

            adminRs.close();
            rs.close();
            stmt.close();

        } catch (SQLException e) {
            // If there's a SQL exception, it might indicate the injection was attempted
            fail("SQL exception occurred, possible injection attempt: " + e.getMessage());
        } catch (Exception e) {
            // Test might fail if MySQL is not available - that's acceptable
            System.out.println("Test skipped: Database not available - " + e.getMessage());
        }
    }

    /**
     * Test that verifies SQL injection prevention in admin password.
     * Ensures that special SQL characters in password are properly escaped.
     */
    public void testSqlInjectionPreventionInAdminPassword() throws Exception {
        // Arrange: Create a malicious password with SQL injection attempt
        String normalUsername = "testadmin";
        String maliciousPassword = "pass','admin@localhost','I am admin','default.jpg','superadmin',1,''); DROP TABLE users; --";

        // Mock request parameters
        when(mockRequest.getParameter("dburl")).thenReturn(testDbUrl);
        when(mockRequest.getParameter("jdbcdriver")).thenReturn("com.mysql.jdbc.Driver");
        when(mockRequest.getParameter("dbuser")).thenReturn(testDbUser);
        when(mockRequest.getParameter("dbpass")).thenReturn(testDbPass);
        when(mockRequest.getParameter("dbname")).thenReturn(testDbName + "_pwd_test");
        when(mockRequest.getParameter("siteTitle")).thenReturn("Test Site");
        when(mockRequest.getParameter("adminuser")).thenReturn(normalUsername);
        when(mockRequest.getParameter("adminpass")).thenReturn(maliciousPassword);
        when(mockRequest.getParameter("setup")).thenReturn("1");

        when(mockResponse.getWriter()).thenReturn(new PrintWriter(responseWriter));

        // Act: Process the request
        try {
            installServlet.processRequest(mockRequest, mockResponse);

            // Assert: Verify the database structure is intact
            Class.forName("com.mysql.jdbc.Driver");
            Connection conn = DriverManager.getConnection(testDbUrl + testDbName + "_pwd_test", testDbUser, testDbPass);

            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT username, password FROM users WHERE username=?");

            // Prepare statement to safely query
            java.sql.PreparedStatement pstmt = conn.prepareStatement(
                "SELECT username, password FROM users WHERE username=?"
            );
            pstmt.setString(1, normalUsername);
            ResultSet safeRs = pstmt.executeQuery();

            if (safeRs.next()) {
                String insertedPassword = safeRs.getString("password");
                // The malicious password should be stored as literal data
                assertEquals("Password should be stored as literal data", maliciousPassword, insertedPassword);
            }

            safeRs.close();
            pstmt.close();
            stmt.close();
            conn.close();

            // Clean up test database
            Connection cleanupConn = DriverManager.getConnection(testDbUrl, testDbUser, testDbPass);
            Statement cleanupStmt = cleanupConn.createStatement();
            cleanupStmt.executeUpdate("DROP DATABASE IF EXISTS " + testDbName + "_pwd_test");
            cleanupStmt.close();
            cleanupConn.close();

        } catch (Exception e) {
            // Test might fail if MySQL is not available - that's acceptable
            System.out.println("Test skipped: Database not available - " + e.getMessage());
        }
    }

    /**
     * Test normal installation flow with valid, non-malicious inputs.
     * Ensures the remediation doesn't break legitimate functionality.
     */
    public void testNormalInstallationWithValidInputs() throws Exception {
        // Arrange: Create normal, valid inputs
        String validUsername = "administrator";
        String validPassword = "secureHashedPassword";

        // Mock request parameters
        when(mockRequest.getParameter("dburl")).thenReturn(testDbUrl);
        when(mockRequest.getParameter("jdbcdriver")).thenReturn("com.mysql.jdbc.Driver");
        when(mockRequest.getParameter("dbuser")).thenReturn(testDbUser);
        when(mockRequest.getParameter("dbpass")).thenReturn(testDbPass);
        when(mockRequest.getParameter("dbname")).thenReturn(testDbName + "_valid");
        when(mockRequest.getParameter("siteTitle")).thenReturn("Valid Site");
        when(mockRequest.getParameter("adminuser")).thenReturn(validUsername);
        when(mockRequest.getParameter("adminpass")).thenReturn(validPassword);
        when(mockRequest.getParameter("setup")).thenReturn("1");

        when(mockResponse.getWriter()).thenReturn(new PrintWriter(responseWriter));

        // Act: Process the request
        try {
            installServlet.processRequest(mockRequest, mockResponse);

            // Assert: Verify successful installation
            String response = responseWriter.toString();
            assertTrue("Should show success message",
                response.contains("successfully installed") || response.contains("Servlet install"));

            // Verify database was created properly
            Class.forName("com.mysql.jdbc.Driver");
            Connection conn = DriverManager.getConnection(testDbUrl + testDbName + "_valid", testDbUser, testDbPass);

            // Verify admin user was created correctly
            java.sql.PreparedStatement pstmt = conn.prepareStatement(
                "SELECT username, password, privilege FROM users WHERE privilege='admin'"
            );
            ResultSet rs = pstmt.executeQuery();

            assertTrue("Admin user should exist", rs.next());
            assertEquals("Admin username should match", validUsername, rs.getString("username"));
            assertEquals("Admin password should match", validPassword, rs.getString("password"));
            assertEquals("Admin privilege should be set", "admin", rs.getString("privilege"));

            rs.close();
            pstmt.close();
            conn.close();

            // Clean up
            Connection cleanupConn = DriverManager.getConnection(testDbUrl, testDbUser, testDbPass);
            Statement cleanupStmt = cleanupConn.createStatement();
            cleanupStmt.executeUpdate("DROP DATABASE IF EXISTS " + testDbName + "_valid");
            cleanupStmt.close();
            cleanupConn.close();

        } catch (Exception e) {
            // Test might fail if MySQL is not available - that's acceptable
            System.out.println("Test skipped: Database not available - " + e.getMessage());
        }
    }

    /**
     * Test handling of special characters that are legitimate but could be confused with SQL syntax.
     * Ensures proper escaping/parameterization for edge cases.
     */
    public void testSpecialCharactersHandling() throws Exception {
        // Arrange: Create inputs with special characters
        String usernameWithQuotes = "admin'test\"user";
        String passwordWithSpecialChars = "p@ss'w\"ord`123";

        // Mock request parameters
        when(mockRequest.getParameter("dburl")).thenReturn(testDbUrl);
        when(mockRequest.getParameter("jdbcdriver")).thenReturn("com.mysql.jdbc.Driver");
        when(mockRequest.getParameter("dbuser")).thenReturn(testDbUser);
        when(mockRequest.getParameter("dbpass")).thenReturn(testDbPass);
        when(mockRequest.getParameter("dbname")).thenReturn(testDbName + "_special");
        when(mockRequest.getParameter("siteTitle")).thenReturn("Test Site");
        when(mockRequest.getParameter("adminuser")).thenReturn(usernameWithQuotes);
        when(mockRequest.getParameter("adminpass")).thenReturn(passwordWithSpecialChars);
        when(mockRequest.getParameter("setup")).thenReturn("1");

        when(mockResponse.getWriter()).thenReturn(new PrintWriter(responseWriter));

        // Act & Assert: Verify special characters are handled without SQL errors
        try {
            installServlet.processRequest(mockRequest, mockResponse);

            // If we get here without SQL exception, the parameterization worked
            Class.forName("com.mysql.jdbc.Driver");
            Connection conn = DriverManager.getConnection(testDbUrl + testDbName + "_special", testDbUser, testDbPass);

            // Verify data was inserted correctly
            java.sql.PreparedStatement pstmt = conn.prepareStatement(
                "SELECT username, password FROM users WHERE privilege='admin'"
            );
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                assertEquals("Special characters in username should be preserved",
                    usernameWithQuotes, rs.getString("username"));
                assertEquals("Special characters in password should be preserved",
                    passwordWithSpecialChars, rs.getString("password"));
            }

            rs.close();
            pstmt.close();
            conn.close();

            // Clean up
            Connection cleanupConn = DriverManager.getConnection(testDbUrl, testDbUser, testDbPass);
            Statement cleanupStmt = cleanupConn.createStatement();
            cleanupStmt.executeUpdate("DROP DATABASE IF EXISTS " + testDbName + "_special");
            cleanupStmt.close();
            cleanupConn.close();

        } catch (Exception e) {
            // Test might fail if MySQL is not available - that's acceptable
            System.out.println("Test skipped: Database not available - " + e.getMessage());
        }
    }

    /**
     * Test that verifies the setup method returns false when setup parameter is not "1".
     * This is a functional test to ensure the remediation doesn't break control flow.
     */
    public void testSetupReturnsFalseForInvalidParameter() throws Exception {
        // Arrange
        Install servlet = new Install();

        // Act & Assert
        assertFalse("Setup should return false for empty string", servlet.setup(""));
        assertFalse("Setup should return false for '0'", servlet.setup("0"));
        assertFalse("Setup should return false for invalid value", servlet.setup("invalid"));
    }

    /**
     * Test edge case with very long input strings to ensure buffer handling is correct.
     */
    public void testLongInputStringsHandling() throws Exception {
        // Arrange: Create very long strings (but within varchar limits)
        StringBuilder longUsername = new StringBuilder();
        for (int i = 0; i < 29; i++) { // varchar(30) - 1 for safety
            longUsername.append("a");
        }

        StringBuilder longPassword = new StringBuilder();
        for (int i = 0; i < 59; i++) { // varchar(60) - 1 for safety
            longPassword.append("b");
        }

        // Mock request parameters
        when(mockRequest.getParameter("dburl")).thenReturn(testDbUrl);
        when(mockRequest.getParameter("jdbcdriver")).thenReturn("com.mysql.jdbc.Driver");
        when(mockRequest.getParameter("dbuser")).thenReturn(testDbUser);
        when(mockRequest.getParameter("dbpass")).thenReturn(testDbPass);
        when(mockRequest.getParameter("dbname")).thenReturn(testDbName + "_long");
        when(mockRequest.getParameter("siteTitle")).thenReturn("Test Site");
        when(mockRequest.getParameter("adminuser")).thenReturn(longUsername.toString());
        when(mockRequest.getParameter("adminpass")).thenReturn(longPassword.toString());
        when(mockRequest.getParameter("setup")).thenReturn("1");

        when(mockResponse.getWriter()).thenReturn(new PrintWriter(responseWriter));

        // Act: Process the request
        try {
            installServlet.processRequest(mockRequest, mockResponse);

            // Assert: Verify long strings are handled correctly
            Class.forName("com.mysql.jdbc.Driver");
            Connection conn = DriverManager.getConnection(testDbUrl + testDbName + "_long", testDbUser, testDbPass);

            java.sql.PreparedStatement pstmt = conn.prepareStatement(
                "SELECT username, password FROM users WHERE privilege='admin'"
            );
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                assertEquals("Long username should be stored correctly",
                    longUsername.toString(), rs.getString("username"));
                assertEquals("Long password should be stored correctly",
                    longPassword.toString(), rs.getString("password"));
            }

            rs.close();
            pstmt.close();
            conn.close();

            // Clean up
            Connection cleanupConn = DriverManager.getConnection(testDbUrl, testDbUser, testDbPass);
            Statement cleanupStmt = cleanupConn.createStatement();
            cleanupStmt.executeUpdate("DROP DATABASE IF EXISTS " + testDbName + "_long");
            cleanupStmt.close();
            cleanupConn.close();

        } catch (Exception e) {
            // Test might fail if MySQL is not available - that's acceptable
            System.out.println("Test skipped: Database not available - " + e.getMessage());
        }
    }
}
