package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;
import java.lang.reflect.Method;

/**
 * Comprehensive test suite for Install servlet to ensure SQL injection
 * vulnerability is properly remediated.
 *
 * This test class validates:
 * 1. Valid database names are accepted
 * 2. Malicious SQL injection attempts are blocked
 * 3. Edge cases and boundary conditions are handled correctly
 *
 * @author Security Remediation Team
 */
public class InstallTest extends TestCase {

    private Install installServlet;
    private Method isValidDatabaseNameMethod;

    /**
     * Set up test fixtures before each test method.
     */
    protected void setUp() throws Exception {
        super.setUp();
        installServlet = new Install();

        // Use reflection to access the private isValidDatabaseName method
        isValidDatabaseNameMethod = Install.class.getDeclaredMethod("isValidDatabaseName", String.class);
        isValidDatabaseNameMethod.setAccessible(true);
    }

    /**
     * Clean up after each test method.
     */
    protected void tearDown() throws Exception {
        super.tearDown();
        installServlet = null;
        isValidDatabaseNameMethod = null;
    }

    /**
     * Helper method to invoke the private isValidDatabaseName method.
     */
    private boolean invokeIsValidDatabaseName(String databaseName) throws Exception {
        return (Boolean) isValidDatabaseNameMethod.invoke(installServlet, databaseName);
    }

    // ========== POSITIVE TEST CASES: Valid Database Names ==========

    /**
     * Test that simple alphanumeric database names are accepted.
     */
    public void testValidDatabaseName_Simple() throws Exception {
        assertTrue("Simple database name should be valid",
                   invokeIsValidDatabaseName("mydb"));
    }

    /**
     * Test that database names with underscores are accepted.
     */
    public void testValidDatabaseName_WithUnderscores() throws Exception {
        assertTrue("Database name with underscores should be valid",
                   invokeIsValidDatabaseName("my_database_name"));
    }

    /**
     * Test that database names starting with underscore are accepted.
     */
    public void testValidDatabaseName_StartingWithUnderscore() throws Exception {
        assertTrue("Database name starting with underscore should be valid",
                   invokeIsValidDatabaseName("_privatedb"));
    }

    /**
     * Test that database names with mixed case are accepted.
     */
    public void testValidDatabaseName_MixedCase() throws Exception {
        assertTrue("Mixed case database name should be valid",
                   invokeIsValidDatabaseName("MyDatabaseName"));
    }

    /**
     * Test that database names with numbers (not at start) are accepted.
     */
    public void testValidDatabaseName_WithNumbers() throws Exception {
        assertTrue("Database name with numbers should be valid",
                   invokeIsValidDatabaseName("database123"));
        assertTrue("Database name with numbers in middle should be valid",
                   invokeIsValidDatabaseName("db123test"));
    }

    /**
     * Test that single character database name is accepted.
     */
    public void testValidDatabaseName_SingleCharacter() throws Exception {
        assertTrue("Single letter database name should be valid",
                   invokeIsValidDatabaseName("a"));
        assertTrue("Single underscore database name should be valid",
                   invokeIsValidDatabaseName("_"));
    }

    /**
     * Test maximum allowed length (64 characters for MySQL).
     */
    public void testValidDatabaseName_MaxLength() throws Exception {
        // MySQL allows up to 64 characters for database names
        String maxLengthName = "a123456789012345678901234567890123456789012345678901234567890123";
        assertEquals("Max length name should be 64 characters", 64, maxLengthName.length());
        assertTrue("64 character database name should be valid",
                   invokeIsValidDatabaseName(maxLengthName));
    }

    // ========== NEGATIVE TEST CASES: SQL Injection Attempts ==========

    /**
     * Test that SQL injection with DROP TABLE is blocked.
     */
    public void testInvalidDatabaseName_SQLInjection_DropTable() throws Exception {
        assertFalse("SQL injection with DROP TABLE should be blocked",
                    invokeIsValidDatabaseName("mydb; DROP TABLE users;--"));
    }

    /**
     * Test that SQL injection with semicolon is blocked.
     */
    public void testInvalidDatabaseName_SQLInjection_Semicolon() throws Exception {
        assertFalse("Database name with semicolon should be invalid",
                    invokeIsValidDatabaseName("mydb;"));
    }

    /**
     * Test that SQL injection with quotes is blocked.
     */
    public void testInvalidDatabaseName_SQLInjection_SingleQuote() throws Exception {
        assertFalse("Database name with single quote should be invalid",
                    invokeIsValidDatabaseName("mydb'"));
        assertFalse("SQL injection with quote should be blocked",
                    invokeIsValidDatabaseName("' OR '1'='1"));
    }

    /**
     * Test that SQL injection with double quotes is blocked.
     */
    public void testInvalidDatabaseName_SQLInjection_DoubleQuote() throws Exception {
        assertFalse("Database name with double quote should be invalid",
                    invokeIsValidDatabaseName("mydb\""));
    }

    /**
     * Test that SQL injection with comment syntax is blocked.
     */
    public void testInvalidDatabaseName_SQLInjection_Comment() throws Exception {
        assertFalse("SQL injection with -- comment should be blocked",
                    invokeIsValidDatabaseName("mydb--"));
        assertFalse("SQL injection with /* comment should be blocked",
                    invokeIsValidDatabaseName("mydb/*"));
        assertFalse("SQL injection with # comment should be blocked",
                    invokeIsValidDatabaseName("mydb#"));
    }

    /**
     * Test that SQL injection with UNION SELECT is blocked.
     */
    public void testInvalidDatabaseName_SQLInjection_UnionSelect() throws Exception {
        assertFalse("SQL injection with UNION SELECT should be blocked",
                    invokeIsValidDatabaseName("mydb UNION SELECT * FROM users"));
    }

    /**
     * Test that SQL injection with backticks is blocked.
     */
    public void testInvalidDatabaseName_SQLInjection_Backtick() throws Exception {
        assertFalse("Database name with backtick should be invalid",
                    invokeIsValidDatabaseName("`mydb`"));
    }

    /**
     * Test that SQL injection attempting to escape quotes is blocked.
     */
    public void testInvalidDatabaseName_SQLInjection_EscapeAttempt() throws Exception {
        assertFalse("SQL injection with backslash should be blocked",
                    invokeIsValidDatabaseName("mydb\\"));
        assertFalse("SQL injection with escape sequence should be blocked",
                    invokeIsValidDatabaseName("mydb\\'"));
    }

    // ========== NEGATIVE TEST CASES: Invalid Characters ==========

    /**
     * Test that database names with spaces are rejected.
     */
    public void testInvalidDatabaseName_WithSpaces() throws Exception {
        assertFalse("Database name with spaces should be invalid",
                    invokeIsValidDatabaseName("my database"));
        assertFalse("Database name with leading space should be invalid",
                    invokeIsValidDatabaseName(" mydb"));
        assertFalse("Database name with trailing space should be invalid",
                    invokeIsValidDatabaseName("mydb "));
    }

    /**
     * Test that database names starting with a number are rejected.
     */
    public void testInvalidDatabaseName_StartingWithNumber() throws Exception {
        assertFalse("Database name starting with number should be invalid",
                    invokeIsValidDatabaseName("123database"));
    }

    /**
     * Test that database names with special characters are rejected.
     */
    public void testInvalidDatabaseName_SpecialCharacters() throws Exception {
        assertFalse("Database name with dash should be invalid",
                    invokeIsValidDatabaseName("my-database"));
        assertFalse("Database name with dot should be invalid",
                    invokeIsValidDatabaseName("my.database"));
        assertFalse("Database name with @ should be invalid",
                    invokeIsValidDatabaseName("my@database"));
        assertFalse("Database name with $ should be invalid",
                    invokeIsValidDatabaseName("my$database"));
        assertFalse("Database name with & should be invalid",
                    invokeIsValidDatabaseName("my&database"));
        assertFalse("Database name with % should be invalid",
                    invokeIsValidDatabaseName("my%database"));
    }

    /**
     * Test that database names with parentheses are rejected.
     */
    public void testInvalidDatabaseName_Parentheses() throws Exception {
        assertFalse("Database name with parentheses should be invalid",
                    invokeIsValidDatabaseName("mydb()"));
    }

    // ========== NEGATIVE TEST CASES: Edge Cases ==========

    /**
     * Test that null database name is rejected.
     */
    public void testInvalidDatabaseName_Null() throws Exception {
        assertFalse("Null database name should be invalid",
                    invokeIsValidDatabaseName(null));
    }

    /**
     * Test that empty database name is rejected.
     */
    public void testInvalidDatabaseName_Empty() throws Exception {
        assertFalse("Empty database name should be invalid",
                    invokeIsValidDatabaseName(""));
    }

    /**
     * Test that database name exceeding maximum length is rejected.
     */
    public void testInvalidDatabaseName_TooLong() throws Exception {
        // Create a 65 character string (one character over the MySQL limit)
        String tooLongName = "a1234567890123456789012345678901234567890123456789012345678901234";
        assertEquals("Name should be 65 characters", 65, tooLongName.length());
        assertFalse("Database name over 64 characters should be invalid",
                    invokeIsValidDatabaseName(tooLongName));
    }

    /**
     * Test that database name with newline is rejected.
     */
    public void testInvalidDatabaseName_Newline() throws Exception {
        assertFalse("Database name with newline should be invalid",
                    invokeIsValidDatabaseName("mydb\n"));
        assertFalse("Database name with embedded newline should be invalid",
                    invokeIsValidDatabaseName("my\ndb"));
    }

    /**
     * Test that database name with tab is rejected.
     */
    public void testInvalidDatabaseName_Tab() throws Exception {
        assertFalse("Database name with tab should be invalid",
                    invokeIsValidDatabaseName("mydb\t"));
    }

    /**
     * Test that database name with carriage return is rejected.
     */
    public void testInvalidDatabaseName_CarriageReturn() throws Exception {
        assertFalse("Database name with carriage return should be invalid",
                    invokeIsValidDatabaseName("mydb\r"));
    }

    // ========== ADVANCED SQL INJECTION TEST CASES ==========

    /**
     * Test that encoded SQL injection attempts are blocked.
     */
    public void testInvalidDatabaseName_SQLInjection_URLEncoded() throws Exception {
        assertFalse("URL encoded SQL injection should be blocked",
                    invokeIsValidDatabaseName("mydb%27"));
    }

    /**
     * Test that SQL injection with nested queries is blocked.
     */
    public void testInvalidDatabaseName_SQLInjection_NestedQuery() throws Exception {
        assertFalse("Nested query injection should be blocked",
                    invokeIsValidDatabaseName("mydb); SELECT * FROM (SELECT * FROM users"));
    }

    /**
     * Test that SQL injection with multiple statements is blocked.
     */
    public void testInvalidDatabaseName_SQLInjection_MultipleStatements() throws Exception {
        assertFalse("Multiple statement injection should be blocked",
                    invokeIsValidDatabaseName("mydb; DELETE FROM users; SELECT * FROM cards;--"));
    }

    /**
     * Test that boolean-based blind SQL injection is blocked.
     */
    public void testInvalidDatabaseName_SQLInjection_BooleanBlind() throws Exception {
        assertFalse("Boolean blind SQL injection should be blocked",
                    invokeIsValidDatabaseName("mydb' AND '1'='1"));
        assertFalse("Boolean blind SQL injection (false) should be blocked",
                    invokeIsValidDatabaseName("mydb' AND '1'='2"));
    }

    /**
     * Test that time-based blind SQL injection syntax is blocked.
     */
    public void testInvalidDatabaseName_SQLInjection_TimeBased() throws Exception {
        assertFalse("Time-based SQL injection should be blocked",
                    invokeIsValidDatabaseName("mydb'; WAITFOR DELAY '00:00:05'--"));
        assertFalse("MySQL SLEEP injection should be blocked",
                    invokeIsValidDatabaseName("mydb' AND SLEEP(5)--"));
    }

    /**
     * Test real-world attack patterns from the application context.
     * The vulnerable line was: stmt.executeUpdate("DROP DATABASE IF EXISTS "+dbname);
     * These tests ensure such attacks are now prevented.
     */
    public void testInvalidDatabaseName_RealWorldAttacks() throws Exception {
        // Attempt to drop all databases
        assertFalse("Attack to drop all databases should be blocked",
                    invokeIsValidDatabaseName("mydb; DROP DATABASE mysql;--"));

        // Attempt to create malicious stored procedure
        assertFalse("Attack with CREATE PROCEDURE should be blocked",
                    invokeIsValidDatabaseName("mydb; CREATE PROCEDURE malicious() BEGIN END;--"));

        // Attempt to access sensitive tables
        assertFalse("Attack to access cards table should be blocked",
                    invokeIsValidDatabaseName("mydb' UNION SELECT * FROM cards WHERE '1'='1"));
    }

    /**
     * Test that case variations of valid names work correctly.
     */
    public void testValidDatabaseName_CaseVariations() throws Exception {
        assertTrue("Uppercase database name should be valid",
                   invokeIsValidDatabaseName("MYDB"));
        assertTrue("Lowercase database name should be valid",
                   invokeIsValidDatabaseName("mydb"));
        assertTrue("Mixed case database name should be valid",
                   invokeIsValidDatabaseName("MyDb"));
    }
}
