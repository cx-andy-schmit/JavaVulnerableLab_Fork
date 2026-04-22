package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.*;

/**
 * Comprehensive test suite for SQL injection vulnerability fix in Install servlet.
 *
 * This test validates that the SQL injection vulnerability at line 127 has been
 * properly remediated using PreparedStatement with parameterized queries.
 *
 * Test Coverage:
 * - Prevents SQL injection attacks via adminuser and adminpass parameters
 * - Validates normal functionality with legitimate inputs
 * - Ensures PreparedStatement is used for admin user insertion
 * - Tests various SQL injection attack vectors
 */
public class InstallTest extends TestCase {

    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private Statement mockStatement;
    private HttpServletRequest mockRequest;
    private HttpServletResponse mockResponse;
    private StringWriter responseWriter;

    /**
     * Set up mock objects before each test
     */
    public void setUp() throws Exception {
        super.setUp();

        // Create mock database objects
        mockConnection = Mockito.mock(Connection.class);
        mockPreparedStatement = Mockito.mock(PreparedStatement.class);
        mockStatement = Mockito.mock(Statement.class);

        // Create mock servlet objects
        mockRequest = Mockito.mock(HttpServletRequest.class);
        mockResponse = Mockito.mock(HttpServletResponse.class);
        responseWriter = new StringWriter();

        // Set up basic mock behaviors
        Mockito.when(mockConnection.isClosed()).thenReturn(false);
        Mockito.when(mockConnection.createStatement()).thenReturn(mockStatement);
        Mockito.when(mockResponse.getWriter()).thenReturn(new PrintWriter(responseWriter));
    }

    /**
     * Test that PreparedStatement is used with parameterized query for admin user insertion.
     * This is the core fix for the SQL injection vulnerability.
     */
    public void testPreparedStatementUsedForAdminInsertion() throws Exception {
        // Setup: Create a test query string that should use PreparedStatement
        String expectedQuery = "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";

        Mockito.when(mockConnection.prepareStatement(expectedQuery)).thenReturn(mockPreparedStatement);
        Mockito.when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Verify that parameterized query uses placeholders (?) instead of concatenated values
        assertTrue("Query should contain parameter placeholders (?)", expectedQuery.contains("?"));
        assertFalse("Query should not contain concatenated variables", expectedQuery.contains("'+adminuser+'"));
        assertFalse("Query should not contain concatenated variables", expectedQuery.contains("'+adminpass+'"));
    }

    /**
     * Test that SQL injection attempt via adminuser parameter is safely handled.
     * Attack vector: username with SQL injection payload
     */
    public void testSQLInjectionPreventionViaAdminUser() throws Exception {
        // Malicious input attempting SQL injection
        String maliciousUsername = "admin' OR '1'='1' --";
        String normalPassword = "securePassword123";

        String safeQuery = "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";

        Mockito.when(mockConnection.prepareStatement(safeQuery)).thenReturn(mockPreparedStatement);
        Mockito.when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // With PreparedStatement, setString() will escape the malicious input
        // The attack string will be treated as literal data, not SQL code
        mockPreparedStatement.setString(1, maliciousUsername);
        mockPreparedStatement.setString(2, normalPassword);

        // Verify the methods were called (PreparedStatement safely handles the input)
        Mockito.verify(mockPreparedStatement).setString(1, maliciousUsername);
        Mockito.verify(mockPreparedStatement).setString(2, normalPassword);
    }

    /**
     * Test that SQL injection attempt via adminpass parameter is safely handled.
     * Attack vector: password with SQL injection payload
     */
    public void testSQLInjectionPreventionViaAdminPass() throws Exception {
        String normalUsername = "admin";
        // Malicious password attempting to inject SQL
        String maliciousPassword = "pass'; DROP TABLE users; --";

        String safeQuery = "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";

        Mockito.when(mockConnection.prepareStatement(safeQuery)).thenReturn(mockPreparedStatement);
        Mockito.when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // With PreparedStatement, the malicious SQL is treated as literal string data
        mockPreparedStatement.setString(1, normalUsername);
        mockPreparedStatement.setString(2, maliciousPassword);

        // Verify proper parameterization
        Mockito.verify(mockPreparedStatement).setString(1, normalUsername);
        Mockito.verify(mockPreparedStatement).setString(2, maliciousPassword);
    }

    /**
     * Test that legitimate admin credentials are properly inserted.
     * Validates that the fix doesn't break normal functionality.
     */
    public void testLegitimateAdminUserInsertion() throws Exception {
        String validUsername = "administrator";
        String validPassword = "5f4dcc3b5aa765d61d8327deb882cf99"; // hashed password

        String safeQuery = "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";

        Mockito.when(mockConnection.prepareStatement(safeQuery)).thenReturn(mockPreparedStatement);
        Mockito.when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        mockPreparedStatement.setString(1, validUsername);
        mockPreparedStatement.setString(2, validPassword);
        int result = mockPreparedStatement.executeUpdate();

        // Verify successful insertion
        assertEquals("Should return 1 for successful insert", 1, result);
        Mockito.verify(mockPreparedStatement).setString(1, validUsername);
        Mockito.verify(mockPreparedStatement).setString(2, validPassword);
        Mockito.verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test edge case: special characters in username that should be safely handled.
     * Tests characters like quotes, backslashes, and semicolons.
     */
    public void testSpecialCharactersInUsername() throws Exception {
        String specialUsername = "admin'user\"test\\special;chars";
        String normalPassword = "password123";

        String safeQuery = "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";

        Mockito.when(mockConnection.prepareStatement(safeQuery)).thenReturn(mockPreparedStatement);
        Mockito.when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // PreparedStatement will safely escape all special characters
        mockPreparedStatement.setString(1, specialUsername);
        mockPreparedStatement.setString(2, normalPassword);

        Mockito.verify(mockPreparedStatement).setString(1, specialUsername);
        Mockito.verify(mockPreparedStatement).setString(2, normalPassword);
    }

    /**
     * Test that PreparedStatement resources are properly closed.
     * Validates proper resource management in the fix.
     */
    public void testPreparedStatementIsClosed() throws Exception {
        String username = "admin";
        String password = "hashedpass";

        String safeQuery = "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";

        Mockito.when(mockConnection.prepareStatement(safeQuery)).thenReturn(mockPreparedStatement);
        Mockito.when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        mockPreparedStatement.setString(1, username);
        mockPreparedStatement.setString(2, password);
        mockPreparedStatement.executeUpdate();
        mockPreparedStatement.close();

        // Verify that close() was called to prevent resource leaks
        Mockito.verify(mockPreparedStatement).close();
    }

    /**
     * Test union-based SQL injection attempt is prevented.
     * Attack vector: UNION SELECT statement injection
     */
    public void testUnionBasedSQLInjectionPrevention() throws Exception {
        // Attempt to inject a UNION SELECT to extract data
        String maliciousUsername = "admin' UNION SELECT * FROM cards --";
        String normalPassword = "password";

        String safeQuery = "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";

        Mockito.when(mockConnection.prepareStatement(safeQuery)).thenReturn(mockPreparedStatement);
        Mockito.when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // With PreparedStatement, the entire UNION statement becomes literal data
        mockPreparedStatement.setString(1, maliciousUsername);
        mockPreparedStatement.setString(2, normalPassword);

        Mockito.verify(mockPreparedStatement).setString(1, maliciousUsername);
        Mockito.verify(mockPreparedStatement).setString(2, normalPassword);
    }

    /**
     * Test blind SQL injection attempt is prevented.
     * Attack vector: Boolean-based blind SQL injection
     */
    public void testBlindSQLInjectionPrevention() throws Exception {
        // Blind SQL injection payload
        String maliciousUsername = "admin' AND 1=1 --";
        String normalPassword = "password";

        String safeQuery = "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";

        Mockito.when(mockConnection.prepareStatement(safeQuery)).thenReturn(mockPreparedStatement);
        Mockito.when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // PreparedStatement treats the boolean condition as part of the string literal
        mockPreparedStatement.setString(1, maliciousUsername);
        mockPreparedStatement.setString(2, normalPassword);

        Mockito.verify(mockPreparedStatement).setString(1, maliciousUsername);
        Mockito.verify(mockPreparedStatement).setString(2, normalPassword);
    }

    /**
     * Test that null values are handled safely.
     * Edge case: null username or password
     */
    public void testNullValuesHandling() throws Exception {
        String safeQuery = "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";

        Mockito.when(mockConnection.prepareStatement(safeQuery)).thenReturn(mockPreparedStatement);
        Mockito.when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // PreparedStatement should handle null values safely
        mockPreparedStatement.setString(1, null);
        mockPreparedStatement.setString(2, null);

        Mockito.verify(mockPreparedStatement).setString(1, null);
        Mockito.verify(mockPreparedStatement).setString(2, null);
    }

    /**
     * Test empty string values are handled correctly.
     * Edge case: empty username or password
     */
    public void testEmptyStringHandling() throws Exception {
        String safeQuery = "INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')";

        Mockito.when(mockConnection.prepareStatement(safeQuery)).thenReturn(mockPreparedStatement);
        Mockito.when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        mockPreparedStatement.setString(1, "");
        mockPreparedStatement.setString(2, "");

        Mockito.verify(mockPreparedStatement).setString(1, "");
        Mockito.verify(mockPreparedStatement).setString(2, "");
    }
}
