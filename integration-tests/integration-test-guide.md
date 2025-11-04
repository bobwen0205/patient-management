# Integration Testing Guide

## 📋 Table of Contents
1. [Overview](#overview)
2. [Project Structure](#project-structure)
3. [Technology Stack](#technology-stack)
4. [Test Architecture](#test-architecture)
5. [Authentication Tests](#authentication-tests)
6. [Patient API Tests](#patient-api-tests)
7. [Best Practices](#best-practices)
8. [Running Tests](#running-tests)
9. [Common Patterns](#common-patterns)

---

## Overview

Integration tests verify that different components of the application work together correctly. Unlike unit tests that test individual components in isolation, integration tests ensure that the API endpoints, authentication mechanisms, and data flow operate as expected in a real environment.

### Purpose
- Validate end-to-end functionality of API endpoints
- Ensure authentication and authorization work correctly
- Test real HTTP request/response cycles
- Verify data integration between services
- Catch issues that unit tests might miss

### Test Environment
- **Base URL**: `http://localhost:4004`
- **Test Framework**: JUnit 5
- **HTTP Client**: REST Assured
- **Java Version**: 21

---

## Project Structure

```
integration-tests/
├── pom.xml
└── src/
    └── test/
        └── java/
            ├── AuthIntegrationTest.java
            └── PatientIntegrationTest.java
```

### Maven Configuration (`pom.xml`)

**Project Coordinates**
- **Group ID**: `com.pm`
- **Artifact ID**: `integration-tests`
- **Version**: `1.0-SNAPSHOT`

**Dependencies**
1. **REST Assured** (v5.3.0)
   - Purpose: Simplified REST API testing
   - Scope: Test only
   
2. **JUnit Jupiter** (v5.11.4)
   - Purpose: Test framework and assertions
   - Scope: Test only

---

## Technology Stack

### REST Assured
REST Assured is a Java DSL for testing REST APIs. It provides a fluent interface for:
- Sending HTTP requests (GET, POST, PUT, DELETE)
- Setting headers and parameters
- Validating responses
- Extracting data from responses

**Key Features Used**:
- `given()` - Setup request specifications
- `when()` - Execute the HTTP request
- `then()` - Validate the response
- `extract()` - Extract data from response

### JUnit 5 (Jupiter)
Modern testing framework for Java with:
- `@BeforeAll` - Setup executed once before all tests
- `@Test` - Marks test methods
- Improved assertions and assumptions
- Better parameterized testing support

---

## Test Architecture

### AAA Pattern (Arrange-Act-Assert)
All tests follow this structured approach:

1. **Arrange**: Set up test data and preconditions
2. **Act**: Execute the operation being tested
3. **Assert**: Verify the expected outcome

### Common Setup Pattern

```java
@BeforeAll
static void setup() {
    RestAssured.baseURI = "http://localhost:4004";
}
```

This static method runs once before all tests in the class, configuring the base URI for all REST Assured requests.

---

## Authentication Tests

### Test Class: `AuthIntegrationTest`

#### Test 1: Valid Login Flow
**Test Name**: `shouldReturnOkWithValidToken()`

**Purpose**: Verify that valid credentials return a successful response with an authentication token

**Test Flow**:
1. **Arrange**: Create JSON payload with valid credentials
   - Email: `testuser@test.com`
   - Password: `password123`

2. **Act**: Send POST request to `/auth/login`
   - Content-Type: `application/json`
   - Body: Login credentials

3. **Assert**: 
   - Status code is 200 (OK)
   - Response body contains a non-null token
   - Token is printed to console for debugging

**Key Validations**:
- HTTP status code: `200`
- Token field exists and is not null
- Response structure is correct

**Code Breakdown**:
```java
Response response = given()
    .contentType("application/json")  // Set request content type
    .body(loginPayload)               // Attach JSON body
    .when()
    .post("/auth/login")              // Send POST request
    .then()
    .statusCode(200)                  // Validate status
    .body("token", notNullValue())    // Validate token exists
    .extract()
    .response();                      // Extract full response
```

---

#### Test 2: Invalid Login Handling
**Test Name**: `shouldReturnUnauthorizedOnInvalidLogin()`

**Purpose**: Verify that invalid credentials return appropriate error response

**Test Flow**:
1. **Arrange**: Create JSON payload with invalid credentials
   - Email: `invalid_user@test.com`
   - Password: `wrong_password`

2. **Act**: Send POST request to `/auth/login`

3. **Assert**: 
   - Status code is 401 (Unauthorized)

**Key Validations**:
- HTTP status code: `401`
- System correctly rejects invalid credentials
- No token is returned

**Security Implications**:
- Confirms authentication mechanism prevents unauthorized access
- Validates error handling for bad credentials
- Ensures proper HTTP status codes are returned

---

## Patient API Tests

### Test Class: `PatientIntegrationTest`

#### Test: Protected Endpoint Access
**Test Name**: `shouldReturnPatientsWithValidToken()`

**Purpose**: Verify that authenticated users can access protected patient data endpoints

**Test Flow**:
1. **Arrange**: 
   - Create login payload with valid credentials
   - Obtain authentication token via login

2. **Act**: 
   - Send GET request to `/api/patients`
   - Include Bearer token in Authorization header

3. **Assert**:
   - Status code is 200 (OK)
   - Response contains patients data

**Two-Step Process**:

**Step 1: Authentication**
```java
String token = given()
    .contentType("application/json")
    .body(loginPayload)
    .when()
    .post("/auth/login")
    .then()
    .statusCode(200)
    .extract()
    .jsonPath()
    .get("token");
```

**Step 2: Authorized API Call**
```java
given()
    .header("Authorization", "Bearer " + token)
    .when()
    .get("/api/patients")
    .then()
    .statusCode(200)
    .body("patients", notNullValue());
```

**Key Concepts**:
- **Bearer Token Authentication**: Token passed in Authorization header
- **Protected Resources**: Endpoint requires valid authentication
- **Token Extraction**: Using JsonPath to extract token from login response
- **Chained Requests**: Login → API call pattern

---

## Best Practices

### 1. Test Isolation
- Each test should be independent
- Tests should not rely on execution order
- Clean up resources after tests (if needed)

### 2. Clear Test Names
- Use descriptive method names that explain what is being tested
- Follow naming convention: `should[ExpectedBehavior]When[Condition]()`
- Examples:
  - `shouldReturnOkWithValidToken()`
  - `shouldReturnUnauthorizedOnInvalidLogin()`

### 3. AAA Pattern
- Always structure tests with Arrange-Act-Assert
- Use comments to mark sections
- Makes tests more readable and maintainable

### 4. Meaningful Assertions
- Test both success and failure scenarios
- Validate status codes
- Check response body structure
- Verify critical fields are present

### 5. Use Text Blocks for JSON
- Java 15+ text blocks (`"""`) improve readability
- Better than concatenated strings
- Easier to maintain complex JSON payloads

### 6. Console Output for Debugging
- Print important values (like tokens) during development
- Remove or comment out for production test runs
- Helps with troubleshooting failing tests

---

## Running Tests

### Prerequisites
- Java 21 installed
- Maven installed
- Application server running on `localhost:4004`
- Test user account exists in database

### Maven Commands

**Run all tests**:
```bash
mvn test
```

**Run specific test class**:
```bash
mvn test -Dtest=AuthIntegrationTest
```

**Run specific test method**:
```bash
mvn test -Dtest=AuthIntegrationTest#shouldReturnOkWithValidToken
```

**Clean and test**:
```bash
mvn clean test
```

### Environment Setup
1. Start the application server
2. Ensure database is populated with test data
3. Verify test user exists: `testuser@test.com` / `password123`
4. Run integration tests

---

## Common Patterns

### Pattern 1: Login and Extract Token
```java
String token = given()
    .contentType("application/json")
    .body(loginPayload)
    .when()
    .post("/auth/login")
    .then()
    .statusCode(200)
    .extract()
    .jsonPath()
    .get("token");
```

**Use Case**: When you need to authenticate before testing protected endpoints

---

### Pattern 2: Authorized Request
```java
given()
    .header("Authorization", "Bearer " + token)
    .when()
    .get("/api/endpoint")
    .then()
    .statusCode(200);
```

**Use Case**: Testing protected API endpoints that require authentication

---

### Pattern 3: Validate Response Structure
```java
.then()
    .statusCode(200)
    .body("fieldName", notNullValue())
    .body("nestedObject.field", equalTo("expectedValue"));
```

**Use Case**: Ensuring response contains expected data structure

---

### Pattern 4: Extract Full Response
```java
Response response = given()
    .when()
    .get("/api/endpoint")
    .then()
    .extract()
    .response();

String value = response.jsonPath().getString("field");
```

**Use Case**: When you need to extract multiple values or inspect the response

---

## Test Coverage

### Current Coverage
✅ **Authentication**
- Valid login with token generation
- Invalid login rejection

✅ **Patient API**
- Protected endpoint access with valid token

### Recommended Additional Tests
❌ **Authentication**
- Login with missing fields
- Login with malformed JSON
- Token expiration handling
- Logout functionality

❌ **Patient API**
- Access without token (401)
- Access with invalid token (401)
- Access with expired token (401)
- GET single patient by ID
- POST create new patient
- PUT update patient
- DELETE patient

❌ **General**
- CORS handling
- Rate limiting
- Input validation
- Error response formats

---

## Troubleshooting

### Common Issues

**Issue**: Connection refused
- **Solution**: Ensure server is running on `localhost:4004`

**Issue**: 401 Unauthorized on valid credentials
- **Solution**: Verify test user exists in database

**Issue**: Tests pass individually but fail when run together
- **Solution**: Check for test interdependencies; ensure proper isolation

**Issue**: Token extraction returns null
- **Solution**: Verify response structure; check JSON path syntax

**Issue**: Timeout errors
- **Solution**: Increase timeout in REST Assured configuration

---

## Configuration Tips

### Environment-Specific Base URLs
```java
@BeforeAll
static void setup() {
    String env = System.getProperty("test.env", "local");
    RestAssured.baseURI = switch(env) {
        case "dev" -> "https://dev.example.com";
        case "staging" -> "https://staging.example.com";
        default -> "http://localhost:4004";
    };
}
```

### Custom Timeouts
```java
@BeforeAll
static void setup() {
    RestAssured.baseURI = "http://localhost:4004";
    RestAssured.config = RestAssured.config()
        .connectionConfig(ConnectionConfig.connectionConfig()
            .closeIdleConnectionsAfterEachResponse());
}
```

### Logging Requests and Responses
```java
given()
    .log().all()  // Log request
    .when()
    .get("/api/patients")
    .then()
    .log().all()  // Log response
    .statusCode(200);
```

---

## Summary

This integration test suite provides foundational coverage for authentication and patient data access. It demonstrates:

- ✅ REST API testing with REST Assured
- ✅ JWT token-based authentication flow
- ✅ Protected endpoint access patterns
- ✅ Proper test structure and organization
- ✅ Clear, maintainable test code

**Next Steps**:
1. Expand test coverage for additional endpoints
2. Add negative test cases
3. Implement test data management
4. Add performance/load testing
5. Integrate with CI/CD pipeline