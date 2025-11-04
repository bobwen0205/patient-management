# Spring Cloud Gateway - JWT Authentication Implementation Guide

## 📋 Overview

This guide covers implementing JWT (JSON Web Token) authentication in Spring Cloud Gateway through custom filters. The authentication system validates tokens by calling an external auth service before allowing requests to proceed to backend microservices.

**Architecture Pattern:**
```
Client Request → API Gateway → JWT Validation → Auth Service → Backend Service
                      ↓              ↓
                   [Filter]    [Verify Token]
```

---

## 🏗️ Authentication Flow

### Complete Request Flow with JWT

```
1. Client makes request with JWT token
   ↓
2. Request hits API Gateway (port 4004)
   ↓
3. JwtValidationGatewayFilterFactory intercepts request
   ↓
4. Filter extracts Authorization header
   ↓
5. Filter calls Auth Service to validate token
   ↓
6. If valid → proceed to backend service
   If invalid → return 401 Unauthorized
   ↓
7. Response returns to client
```

---

## 📁 Project Structure

```
api-gateway/
└── src/main/java/com/pm/apigateway/
    ├── ApiGatewayApplication.java
    ├── filter/
    │   └── JwtValidationGatewayFilterFactory.java  ← Custom Filter
    ├── exception/
    │   └── JwtValidationException.java             ← Error Handler
    └── resources/
        └── application.yml                         ← Configuration
```

---

## 🔧 Implementation Components

### 1. **JwtValidationGatewayFilterFactory.java**

This is the heart of JWT authentication in the gateway.

```java
@Component
public class JwtValidationGatewayFilterFactory 
    extends AbstractGatewayFilterFactory<Object> {

    private final WebClient webClient;

    public JwtValidationGatewayFilterFactory(
        WebClient.Builder webClientBuilder,
        @Value("${auth.service.url}") String authServiceUrl
    ) {
        this.webClient = webClientBuilder
            .baseUrl(authServiceUrl)
            .build();
    }

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            // 1. Extract Authorization header
            String token = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

            // 2. Validate token format
            if (token == null || !token.startsWith("Bearer ")) {
                exchange.getResponse()
                    .setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
            
            // 3. Call auth service to validate token
            return webClient.get()
                .uri("/validate")
                .header(HttpHeaders.AUTHORIZATION, token)
                .retrieve()
                .toBodilessEntity()
                .then(chain.filter(exchange));
        };
    }
}
```

---

## 🎯 Deep Dive: Understanding Key Concepts

### 1. **AbstractGatewayFilterFactory**

**What is it?**
- Base class for creating custom gateway filters
- Provides structure for filter configuration
- Handles filter instantiation and lifecycle

**Why extend it?**
```java
public class JwtValidationGatewayFilterFactory 
    extends AbstractGatewayFilterFactory<Object>
```

- `<Object>` is the configuration type
- Use `<Object>` when no specific configuration needed
- Use custom class for complex configurations

**Example with Configuration:**
```java
public class MyFilterFactory 
    extends AbstractGatewayFilterFactory<MyFilterFactory.Config> {
    
    public static class Config {
        private String requiredRole;
        private int maxRetries;
        // getters and setters
    }
}
```

---

### 2. **ServerWebExchange** (The `exchange` parameter)

**What is ServerWebExchange?**
- Represents the HTTP request-response exchange
- Container for request and response objects
- Reactive equivalent of HttpServletRequest + HttpServletResponse
- Provides access to request/response data and session

**Structure:**
```java
ServerWebExchange exchange
├── ServerHttpRequest getRequest()     // Incoming request
├── ServerHttpResponse getResponse()   // Outgoing response
├── WebSession getSession()            // Session data
├── Map<String, Object> getAttributes() // Request attributes
└── Principal getPrincipal()           // Authentication info
```

**Common Operations:**

#### Reading Request Data
```java
// Get headers
HttpHeaders headers = exchange.getRequest().getHeaders();
String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
String contentType = headers.getContentType().toString();

// Get request path
String path = exchange.getRequest().getPath().value();

// Get query parameters
MultiValueMap<String, String> params = 
    exchange.getRequest().getQueryParams();
String userId = params.getFirst("userId");

// Get HTTP method
HttpMethod method = exchange.getRequest().getMethod();

// Get remote address
InetSocketAddress address = 
    exchange.getRequest().getRemoteAddress();
```

#### Modifying Request
```java
// Add header to request
ServerHttpRequest modifiedRequest = exchange.getRequest()
    .mutate()
    .header("X-User-Id", "12345")
    .build();

// Create new exchange with modified request
ServerWebExchange modifiedExchange = exchange.mutate()
    .request(modifiedRequest)
    .build();
```

#### Working with Response
```java
// Set status code
exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);

// Add response headers
exchange.getResponse().getHeaders()
    .add("X-Custom-Header", "value");

// Complete response (end the exchange)
return exchange.getResponse().setComplete();

// Write body to response
String body = "{\"error\": \"Unauthorized\"}";
DataBuffer buffer = exchange.getResponse()
    .bufferFactory()
    .wrap(body.getBytes());
return exchange.getResponse().writeWith(Mono.just(buffer));
```

#### Storing Data in Exchange
```java
// Store data for downstream filters
exchange.getAttributes().put("userId", "12345");
exchange.getAttributes().put("roles", List.of("ADMIN", "USER"));

// Retrieve data in another filter
String userId = exchange.getAttribute("userId");
```

---

### 3. **GatewayFilterChain** (The `chain` parameter)

**What is GatewayFilterChain?**
- Represents the chain of filters to execute
- Similar to Servlet Filter Chain
- Allows passing control to next filter
- Returns `Mono<Void>` (reactive completion signal)

**How Chain Works:**

```
Request → Filter 1 → Filter 2 → Filter 3 → Backend Service
             ↓          ↓          ↓
          Before     Before     Before
             ↓          ↓          ↓
          Next       Next       Next
             ↓          ↓          ↓
          After      After      After
Response ←────────────────────────────────
```

**Chain Operations:**

#### Continue to Next Filter
```java
return chain.filter(exchange);
```
- Passes control to next filter in chain
- Returns `Mono<Void>` representing async completion
- Must return this to allow request to proceed

#### Stop Chain (Block Request)
```java
exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
return exchange.getResponse().setComplete();
// Chain is NOT called - request stops here
```

#### Execute Code Before and After Chain
```java
return chain.filter(exchange)
    .doOnSuccess(aVoid -> {
        // This runs AFTER the request completes
        log.info("Request completed successfully");
    })
    .doOnError(error -> {
        // This runs if request fails
        log.error("Request failed: " + error.getMessage());
    });
```

#### Pre-processing and Post-processing
```java
@Override
public GatewayFilter apply(Object config) {
    return (exchange, chain) -> {
        // PRE-PROCESSING (before backend service)
        log.info("Request received: " + exchange.getRequest().getPath());
        long startTime = System.currentTimeMillis();
        
        // Continue chain
        return chain.filter(exchange)
            .then(Mono.fromRunnable(() -> {
                // POST-PROCESSING (after backend service)
                long duration = System.currentTimeMillis() - startTime;
                log.info("Request completed in " + duration + "ms");
                exchange.getResponse().getHeaders()
                    .add("X-Response-Time", duration + "ms");
            }));
    };
}
```

---

### 4. **Reactive Programming with Mono**

**What is Mono?**
- Reactive type representing 0 or 1 element
- Part of Project Reactor (reactive library)
- Non-blocking, asynchronous operations
- Returns immediately without blocking

**Common Mono Operations:**

#### Creating Monos
```java
// Empty Mono
Mono<Void> empty = Mono.empty();

// Mono with value
Mono<String> mono = Mono.just("Hello");

// Mono from supplier
Mono<String> mono = Mono.fromSupplier(() -> "Value");

// Mono from runnable
Mono<Void> mono = Mono.fromRunnable(() -> {
    System.out.println("Do something");
});
```

#### Chaining Operations
```java
webClient.get()
    .retrieve()
    .toBodilessEntity()           // Returns Mono<ResponseEntity<Void>>
    .then(chain.filter(exchange)) // Chain to next operation
    .doOnSuccess(v -> log.info("Success"))
    .doOnError(e -> log.error("Error: " + e))
    .onErrorResume(e -> handleError(e));
```

#### Error Handling
```java
return webClient.get()
    .retrieve()
    .toBodilessEntity()
    .onErrorResume(WebClientResponseException.class, e -> {
        // Handle specific errors
        if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
            exchange.getResponse()
                .setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete()
                .then(Mono.empty());
        }
        return Mono.error(e);
    })
    .then(chain.filter(exchange));
```

---

## 🔍 Line-by-Line Filter Explanation

Let's break down the `apply()` method:

```java
@Override
public GatewayFilter apply(Object config) {
    // Returns a lambda that implements GatewayFilter interface
    return (exchange, chain) -> {
```
**Purpose:** Creates and returns the actual filter logic
- `config`: Configuration object (not used here)
- Returns lambda: `(exchange, chain) -> Mono<Void>`

---

```java
        String token = exchange.getRequest()
            .getHeaders()
            .getFirst(HttpHeaders.AUTHORIZATION);
```
**Purpose:** Extract JWT token from Authorization header
- `exchange.getRequest()`: Get incoming request
- `.getHeaders()`: Get all HTTP headers
- `.getFirst(HttpHeaders.AUTHORIZATION)`: Get "Authorization" header value
- Result: `"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."` or `null`

---

```java
        if (token == null || !token.startsWith("Bearer ")) {
```
**Purpose:** Validate token format
- Checks if header exists
- Checks if it starts with "Bearer " (JWT standard)
- Common formats:
  - ✅ `Bearer eyJhbGci...` (valid)
  - ❌ `null` (missing)
  - ❌ `eyJhbGci...` (missing Bearer prefix)
  - ❌ `Basic dXNlcjpwYXNz` (wrong auth type)

---

```java
            exchange.getResponse()
                .setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
```
**Purpose:** Reject request if token invalid
- Sets HTTP status to 401 Unauthorized
- `setComplete()`: Finalizes response and ends processing
- Chain is NOT called - request stops here
- Returns `Mono<Void>` to satisfy reactive contract

---

```java
        return webClient.get()
            .uri("/validate")
```
**Purpose:** Start HTTP GET request to auth service
- `webClient`: Configured with base URL from `application.yml`
- `.get()`: HTTP GET method
- `.uri("/validate")`: Endpoint path
- Full URL: `http://auth-service:4005/validate`

---

```java
            .header(HttpHeaders.AUTHORIZATION, token)
```
**Purpose:** Forward JWT token to auth service
- Adds Authorization header to validation request
- Auth service will decode and validate the JWT
- Same token that client sent is forwarded

---

```java
            .retrieve()
```
**Purpose:** Execute the HTTP request
- Sends request to auth service
- Returns `ResponseSpec` for further processing
- Non-blocking operation (returns immediately)

---

```java
            .toBodilessEntity()
```
**Purpose:** Get response without reading body
- We only care if request succeeds (200 OK) or fails (401)
- Returns `Mono<ResponseEntity<Void>>`
- More efficient than reading body we don't need
- If auth service returns 401, throws `WebClientResponseException.Unauthorized`

---

```java
            .then(chain.filter(exchange));
```
**Purpose:** Continue to next filter if validation succeeds
- `.then()`: Wait for previous Mono to complete, then execute next
- `chain.filter(exchange)`: Pass to next filter/backend service
- Only executes if token validation succeeded
- If validation fails, exception thrown and this line never executes

---

## 🚨 Exception Handling

### **JwtValidationException.java**

```java
@RestControllerAdvice
public class JwtValidationException {
    
    @ExceptionHandler(WebClientResponseException.Unauthorized.class)
    public Mono<Void> handleUnauthorizedException(
        ServerWebExchange exchange
    ) {
        exchange.getResponse()
            .setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}
```

**Component Breakdown:**

#### @RestControllerAdvice
```java
@RestControllerAdvice
```
- Global exception handler for Spring WebFlux
- Catches exceptions thrown by any component
- Works with reactive applications (unlike @ControllerAdvice)
- Applies to all routes and filters

#### @ExceptionHandler
```java
@ExceptionHandler(WebClientResponseException.Unauthorized.class)
```
- Specifies which exception to catch
- `WebClientResponseException.Unauthorized`: Thrown when auth service returns 401
- This is what `webClient.retrieve()` throws on 401 response

#### Handler Method
```java
public Mono<Void> handleUnauthorizedException(
    ServerWebExchange exchange
) {
    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
    return exchange.getResponse().setComplete();
}
```
- Receives the `ServerWebExchange` (current request/response)
- Sets response status to 401
- Completes response and returns to client
- Returns `Mono<Void>` for reactive flow

**When is this triggered?**

```
1. Client sends request with invalid/expired token
   ↓
2. Filter calls auth service: GET /validate
   ↓
3. Auth service responds with 401 Unauthorized
   ↓
4. WebClient throws WebClientResponseException.Unauthorized
   ↓
5. @ExceptionHandler catches exception
   ↓
6. Returns 401 to client
```

---

## 📝 Configuration: application.yml

```yaml
server:
  port: 4004

spring:
  cloud:
    gateway:
      routes:
        # Protected route - requires JWT
        - id: patient-service-route
          uri: http://patient-service:4000
          predicates:
            - Path=/api/patients/**
          filters:
            - StripPrefix=1
            - JwtValidation  # ← Custom filter applied here
            
        # Public route - no authentication
        - id: api-docs-patient-route
          uri: http://patient-service:4000
          predicates:
            - Path=/api-docs/patients
          filters:
            - RewritePath=/api-docs/patients,/v3/api-docs
            
        # Auth service route - login/register
        - id: auth-service-route
          uri: http://auth-service:4005
          predicates:
            - Path=/auth/**
          filters:
            - StripPrefix=1

auth:
  service:
    url: http://auth-service:4005  # Auth service base URL
```

### Configuration Breakdown

#### Filter Application
```yaml
filters:
  - StripPrefix=1      # Execute first
  - JwtValidation      # Execute second (our custom filter)
```

**Filter Order Matters!**
```
Request: /api/patients/123
         ↓
StripPrefix=1: /patients/123
         ↓
JwtValidation: Validate token
         ↓
Forward: http://patient-service:4000/patients/123
```

#### Custom Property
```yaml
auth:
  service:
    url: http://auth-service:4005
```
- Custom application property
- Injected via `@Value("${auth.service.url}")`
- Configures WebClient base URL
- Allows changing auth service location without code changes

---

## 🔄 Complete Request Flow Example

### Scenario: Get Patient by ID

**1. Client Request**
```http
GET http://localhost:4004/api/patients/123
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**2. Gateway Receives Request**
```
ServerWebExchange created
├── Request
│   ├── Path: /api/patients/123
│   ├── Method: GET
│   └── Headers: {Authorization: Bearer ...}
└── Response: (empty, to be filled)
```

**3. Route Matching**
```yaml
- id: patient-service-route
  predicates:
    - Path=/api/patients/**  ✅ MATCH
```

**4. Filter Chain Execution**

```
Filter 1: StripPrefix=1
├── Input: /api/patients/123
└── Output: /patients/123

Filter 2: JwtValidation
├── Extract token: Bearer eyJ...
├── Validate format: ✅ starts with "Bearer "
├── Call auth service:
│   GET http://auth-service:4005/validate
│   Authorization: Bearer eyJ...
├── Auth service responds: 200 OK
└── Continue to next filter ✅
```

**5. Forward to Backend**
```http
GET http://patient-service:4000/patients/123
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**6. Backend Response**
```json
{
  "id": 123,
  "name": "John Doe",
  "age": 45,
  "diagnosis": "Hypertension"
}
```

**7. Gateway Returns Response**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 123,
  "name": "John Doe",
  "age": 45,
  "diagnosis": "Hypertension"
}
```

---

## 🚫 Failure Scenarios

### Scenario 1: Missing Token

**Request:**
```http
GET http://localhost:4004/api/patients/123
# No Authorization header
```

**Filter Processing:**
```java
String token = exchange.getRequest()
    .getHeaders()
    .getFirst(HttpHeaders.AUTHORIZATION);
// token = null

if (token == null || !token.startsWith("Bearer ")) {
    // ✅ Condition true
    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
    return exchange.getResponse().setComplete();
    // Chain is NOT called - stops here
}
```

**Response:**
```http
HTTP/1.1 401 Unauthorized
```

---

### Scenario 2: Invalid Token Format

**Request:**
```http
GET http://localhost:4004/api/patients/123
Authorization: InvalidToken12345
```

**Filter Processing:**
```java
String token = "InvalidToken12345";

if (token == null || !token.startsWith("Bearer ")) {
    // ✅ Condition true (!token.startsWith("Bearer "))
    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
    return exchange.getResponse().setComplete();
}
```

**Response:**
```http
HTTP/1.1 401 Unauthorized
```

---

### Scenario 3: Expired/Invalid Token

**Request:**
```http
GET http://localhost:4004/api/patients/123
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.expired.token
```

**Filter Processing:**
```java
// Format check passes
return webClient.get()
    .uri("/validate")
    .header(HttpHeaders.AUTHORIZATION, token)
    .retrieve()  // Auth service returns 401
    .toBodilessEntity()  // Throws WebClientResponseException.Unauthorized
    .then(chain.filter(exchange));  // Never reached
```

**Exception Handler Triggered:**
```java
@ExceptionHandler(WebClientResponseException.Unauthorized.class)
public Mono<Void> handleUnauthorizedException(ServerWebExchange exchange) {
    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
    return exchange.getResponse().setComplete();
}
```

**Response:**
```http
HTTP/1.1 401 Unauthorized
```

---

## 🔧 Advanced Filter Patterns

### 1. **Extracting User Info from JWT**

```java
@Override
public GatewayFilter apply(Object config) {
    return (exchange, chain) -> {
        String token = exchange.getRequest()
            .getHeaders()
            .getFirst(HttpHeaders.AUTHORIZATION);

        if (token == null || !token.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        return webClient.get()
            .uri("/validate")
            .header(HttpHeaders.AUTHORIZATION, token)
            .retrieve()
            .bodyToMono(UserInfo.class)  // Get user info instead
            .flatMap(userInfo -> {
                // Add user info to request
                ServerHttpRequest modifiedRequest = exchange.getRequest()
                    .mutate()
                    .header("X-User-Id", userInfo.getId())
                    .header("X-User-Email", userInfo.getEmail())
                    .build();
                
                return chain.filter(
                    exchange.mutate()
                        .request(modifiedRequest)
                        .build()
                );
            });
    };
}
```

---

### 2. **Role-Based Authorization**

```java
public static class Config {
    private List<String> requiredRoles;
    // getters and setters
}

@Override
public GatewayFilter apply(Config config) {
    return (exchange, chain) -> {
        String token = extractToken(exchange);
        
        return webClient.get()
            .uri("/validate")
            .header(HttpHeaders.AUTHORIZATION, token)
            .retrieve()
            .bodyToMono(TokenValidationResponse.class)
            .flatMap(response -> {
                // Check if user has required roles
                boolean hasRole = response.getRoles().stream()
                    .anyMatch(config.getRequiredRoles()::contains);
                
                if (!hasRole) {
                    exchange.getResponse()
                        .setStatusCode(HttpStatus.FORBIDDEN);
                    return exchange.getResponse().setComplete();
                }
                
                return chain.filter(exchange);
            });
    };
}
```

**Usage in YAML:**
```yaml
filters:
  - name: JwtValidation
    args:
      requiredRoles:
        - ADMIN
        - MANAGER
```

---

### 3. **Token Refresh Logic**

```java
@Override
public GatewayFilter apply(Object config) {
    return (exchange, chain) -> {
        String token = extractToken(exchange);
        
        return webClient.get()
            .uri("/validate")
            .header(HttpHeaders.AUTHORIZATION, token)
            .retrieve()
            .bodyToMono(TokenValidationResponse.class)
            .flatMap(response -> {
                if (response.isExpiringSoon()) {
                    // Add header to notify client
                    exchange.getResponse().getHeaders()
                        .add("X-Token-Refresh-Required", "true");
                }
                return chain.filter(exchange);
            })
            .onErrorResume(
                WebClientResponseException.Unauthorized.class,
                e -> {
                    // Try to refresh token
                    return attemptTokenRefresh(exchange)
                        .flatMap(newToken -> {
                            // Retry with new token
                            ServerHttpRequest modifiedRequest = 
                                exchange.getRequest()
                                    .mutate()
                                    .header(HttpHeaders.AUTHORIZATION, 
                                           "Bearer " + newToken)
                                    .build();
                            
                            return chain.filter(
                                exchange.mutate()
                                    .request(modifiedRequest)
                                    .build()
                            );
                        });
                }
            );
    };
}
```

---

### 4. **Rate Limiting with JWT**

```java
@Override
public GatewayFilter apply(Object config) {
    return (exchange, chain) -> {
        String token = extractToken(exchange);
        
        return webClient.get()
            .uri("/validate")
            .header(HttpHeaders.AUTHORIZATION, token)
            .retrieve()
            .bodyToMono(TokenValidationResponse.class)
            .flatMap(response -> {
                String userId = response.getUserId();
                
                // Check rate limit for this user
                return rateLimitService.checkLimit(userId)
                    .flatMap(allowed -> {
                        if (!allowed) {
                            exchange.getResponse()
                                .setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
                            return exchange.getResponse().setComplete();
                        }
                        
                        // Store user ID for downstream services
                        exchange.getAttributes()
                            .put("userId", userId);
                        
                        return chain.filter(exchange);
                    });
            });
    };
}
```

---

### 5. **Logging and Monitoring**

```java
@Override
public GatewayFilter apply(Object config) {
    return (exchange, chain) -> {
        String requestId = UUID.randomUUID().toString();
        long startTime = System.currentTimeMillis();
        
        log.info("Request [{}] started: {} {}", 
            requestId,
            exchange.getRequest().getMethod(),
            exchange.getRequest().getPath()
        );
        
        String token = extractToken(exchange);
        
        return webClient.get()
            .uri("/validate")
            .header(HttpHeaders.AUTHORIZATION, token)
            .retrieve()
            .toBodilessEntity()
            .then(chain.filter(exchange))
            .doOnSuccess(aVoid -> {
                long duration = System.currentTimeMillis() - startTime;
                log.info("Request [{}] succeeded in {}ms", 
                    requestId, duration);
                
                exchange.getResponse().getHeaders()
                    .add("X-Request-Id", requestId);
                exchange.getResponse().getHeaders()
                    .add("X-Response-Time", duration + "ms");
            })
            .doOnError(error -> {
                long duration = System.currentTimeMillis() - startTime;
                log.error("Request [{}] failed after {}ms: {}", 
                    requestId, duration, error.getMessage());
            });
    };
}
```

---

## 🧪 Testing the Authentication

### Using cURL

**1. Request without token**
```bash
curl -X GET http://localhost:4004/api/patients/123
# Expected: 401 Unauthorized
```

**2. Request with invalid format**
```bash
curl -X GET http://localhost:4004/api/patients/123 \
  -H "Authorization: InvalidToken"
# Expected: 401 Unauthorized
```

**3. Request with valid token**
```bash
# First, login to get token
TOKEN=$(curl -X POST http://localhost:4004/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}' \
  | jq -r '.token')

# Then use token
curl -X GET http://localhost:4004/api/patients/123 \
  -H "Authorization: Bearer $TOKEN"
# Expected: 200 OK with patient data
```

**4. Request to public endpoint**
```bash
curl -X GET http://localhost:4004/api-docs/patients
# Expected: 200 OK (no auth required)
```

### Using Postman

**Collection Setup:**

1. **Create Environment Variables:**
   ```
   baseUrl: http://localhost:4004
   token: (empty initially)
   ```

2. **Login Request:**
   ```
   POST {{baseUrl}}/auth/login
   Body: {
     "username": "testuser",
     "password": "password"
   }
   
   Tests:
   pm.environment.set("token", pm.response.json().token);
   ```

3. **Protected Request:**
   ```
   GET {{baseUrl}}/api/patients/123
   Authorization: Bearer {{token}}
   ```

---

## 📊 Monitoring and Debugging

### Enable Debug Logging

**application.yml:**
```yaml
logging:
  level:
    com.pm.apigateway.filter: DEBUG
    org.springframework.cloud.gateway: DEBUG
    org.springframework.web.reactive.function.client: DEBUG
```

### Add Logging to Filter

```java
@Slf4j  // Lombok annotation
@Component
public class JwtValidationGatewayFilterFactory 
    extends AbstractGatewayFilterFactory<Object> {
    
    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            log.debug("JWT validation started for path: {}", 
                exchange.getRequest().getPath());
            
            String token = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);
            
            if (token == null) {
                log.warn("Missing Authorization header");
                exchange.getResponse()
                    .setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
            
            if (!token.startsWith("Bearer ")) {
                log.warn("Invalid token format: {}", 
                    token.substring(0, Math.min(20, token.length())));
                exchange.getResponse()
                    .setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
            
            log.debug("Validating token with auth service");
            
            return webClient.get()
                .uri("/validate")
                .header(HttpHeaders.AUTHORIZATION, token)
                .retrieve()
                .toBodilessEntity()
                .doOnSuccess(response -> {
                    log.debug("Token validated successfully");
                })
                .doOnError(error -> {
                    log.error("Token validation failed: {}", 
                        error.getMessage());
                })
                .then(chain.filter(exchange));
        };
    }
}
```

---

## 🎯 Best Practices

### 1. **Security**
- ✅ Always validate token format before calling auth service
- ✅ Use HTTPS in production
- ✅ Don't log full token values (security risk)
- ✅ Set appropriate timeout for auth service calls
- ✅ Implement token blacklisting for logout

### 2. **Performance**
- ✅ Cache validation results for short periods (if applicable)
- ✅ Use connection pooling for WebClient
- ✅ Set reasonable timeouts to avoid hanging requests
- ✅ Consider using Redis for distributed token cache
- ✅ Monitor auth service response times

### 3. **Error Handling**
- ✅ Handle all possible exceptions gracefully
- ✅ Return appropriate HTTP status codes
- ✅ Don't expose internal error details to clients
- ✅ Log errors with context (request ID, user ID, etc.)
- ✅ Implement circuit breaker for auth service calls

### 4. **Configuration**
- ✅ Externalize auth service URL
- ✅ Make timeouts configurable
- ✅ Use environment-specific configurations
- ✅ Document all configuration properties
- ✅ Validate configuration on startup

### 5. **Testing**
- ✅ Unit test filter logic
- ✅ Integration test with mock auth service
- ✅ Test all failure scenarios
- ✅ Load test authentication flow
- ✅ Test token expiration handling

---

## 🔧 WebClient Configuration

### Basic WebClient Setup

```java
@Configuration
public class WebClientConfig {
    
    @Bean
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder()
            .defaultHeader(HttpHeaders.CONTENT_TYPE, 
                MediaType.APPLICATION_JSON_VALUE)
            .clientConnector(
                new ReactorClientHttpConnector(
                    HttpClient.create()
                        .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                        .doOnConnected(conn -> 
                            conn.addHandlerLast(
                                new ReadTimeoutHandler(5))
                            .addHandlerLast(
                                new WriteTimeoutHandler(5))
                        )
                )
            );
    }
}
```

### Advanced WebClient with Retry and Circuit Breaker

```java
@Configuration
public class WebClientConfig {
    
    @Bean
    public WebClient.Builder webClientBuilder(
        @Value("${auth.service.max-retries:3}") int maxRetries,
        @Value("${auth.service.timeout:5000}") int timeout
    ) {
        return WebClient.builder()
            .filter(ExchangeFilterFunction.ofRequestProcessor(
                clientRequest -> {
                    log.debug("Request: {} {}", 
                        clientRequest.method(), 
                        clientRequest.url());
                    return Mono.just(clientRequest);
                }
            ))
            .filter(ExchangeFilterFunction.ofResponseProcessor(
                clientResponse -> {
                    log.debug("Response: {}", 
                        clientResponse.statusCode());
                    return Mono.just(clientResponse);
                }
            ))
            .clientConnector(
                new ReactorClientHttpConnector(
                    HttpClient.create()
                        .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, timeout)
                        .responseTimeout(Duration.ofMillis(timeout))
                        .doOnConnected(conn -> 
                            conn.addHandlerLast(
                                new ReadTimeoutHandler(timeout / 1000))
                            .addHandlerLast(
                                new WriteTimeoutHandler(timeout / 1000))
                        )
                )
            );
    }
}
```

---

## 🔄 Complete Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT APPLICATION                       │
│                    (Web/Mobile/Desktop App)                      │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ 1. HTTP Request
                         │    GET /api/patients/123
                         │    Authorization: Bearer eyJ...
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                      API GATEWAY (Port 4004)                     │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              Route Matching Layer                          │ │
│  │  - Match predicates (Path, Method, Headers)                │ │
│  │  - Select appropriate route                                │ │
│  └────────────────┬───────────────────────────────────────────┘ │
│                   │                                              │
│                   ▼                                              │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              Filter Chain                                  │ │
│  │                                                            │ │
│  │  ┌──────────────────────────────────────────────────┐    │ │
│  │  │ 1. StripPrefix Filter                            │    │ │
│  │  │    /api/patients/123 → /patients/123             │    │ │
│  │  └──────────────────────────────────────────────────┘    │ │
│  │                   ▼                                       │ │
│  │  ┌──────────────────────────────────────────────────┐    │ │
│  │  │ 2. JwtValidationGatewayFilterFactory             │    │ │
│  │  │                                                   │    │ │
│  │  │  a) Extract Authorization header                 │    │ │
│  │  │  b) Validate format (Bearer ...)                 │    │ │
│  │  │  c) Call Auth Service ──────────┐                │    │ │
│  │  │  d) Wait for validation          │                │    │ │
│  │  │  e) Continue or reject           │                │    │ │
│  │  └──────────────────────────────────┼────────────────┘    │ │
│  │                   ▼                  │                     │ │
│  │  ┌──────────────────────────────────┼────────────────┐    │ │
│  │  │ 3. Additional Filters (if any)   │                │    │ │
│  │  └──────────────────────────────────┼────────────────┘    │ │
│  └───────────────────────────────────┬─┼─────────────────────┘ │
│                                       │ │                       │
└───────────────────────────────────────┼─┼───────────────────────┘
                                        │ │
                    ┌───────────────────┘ └────────────────┐
                    │                                       │
                    │ 4. Validate Token                     │
                    ▼                                       │
    ┌──────────────────────────────┐                       │
    │   AUTH SERVICE (Port 4005)   │                       │
    │                              │                       │
    │  POST /validate              │                       │
    │  Header: Authorization       │                       │
    │                              │                       │
    │  ┌────────────────────────┐  │                       │
    │  │ 1. Decode JWT          │  │                       │
    │  │ 2. Verify signature    │  │                       │
    │  │ 3. Check expiration    │  │                       │
    │  │ 4. Validate claims     │  │                       │
    │  └────────────────────────┘  │                       │
    │                              │                       │
    │  Response: 200 OK or 401     │                       │
    └──────────────┬───────────────┘                       │
                   │                                       │
                   │ 5. Validation Result                  │
                   └───────────────────────────────────────┘
                                   │
                        ┌──────────┴──────────┐
                        │                     │
                   ✅ Valid            ❌ Invalid
                        │                     │
                        ▼                     ▼
          ┌─────────────────────┐   ┌──────────────────┐
          │  Continue to         │   │  Return 401      │
          │  Backend Service     │   │  Unauthorized    │
          └──────────┬───────────┘   └────────┬─────────┘
                     │                        │
                     ▼                        │
    ┌────────────────────────────┐            │
    │ PATIENT SERVICE (Port 4000)│            │
    │                            │            │
    │  GET /patients/123         │            │
    │                            │            │
    │  ┌──────────────────────┐  │            │
    │  │ Business Logic       │  │            │
    │  │ Database Query       │  │            │
    │  │ Build Response       │  │            │
    │  └──────────────────────┘  │            │
    │                            │            │
    │  Response: Patient Data    │            │
    └────────────┬───────────────┘            │
                 │                            │
                 │ 6. Response                │
                 ▼                            │
    ┌────────────────────────────┐            │
    │     API GATEWAY            │◄───────────┘
    │   Forwards Response         │
    └────────────┬───────────────┘
                 │
                 │ 7. Return to Client
                 ▼
    ┌────────────────────────────┐
    │      CLIENT                │
    │  Receives Response         │
    └────────────────────────────┘
```

---

## 🧪 Unit Testing

### Test JwtValidationGatewayFilterFactory

```java
@ExtendWith(MockitoExtension.class)
class JwtValidationGatewayFilterFactoryTest {
    
    @Mock
    private WebClient.Builder webClientBuilder;
    
    @Mock
    private WebClient webClient;
    
    @Mock
    private WebClient.RequestHeadersUriSpec requestHeadersUriSpec;
    
    @Mock
    private WebClient.RequestHeadersSpec requestHeadersSpec;
    
    @Mock
    private WebClient.ResponseSpec responseSpec;
    
    @Mock
    private ServerWebExchange exchange;
    
    @Mock
    private GatewayFilterChain chain;
    
    @Mock
    private ServerHttpRequest request;
    
    @Mock
    private ServerHttpResponse response;
    
    @Mock
    private HttpHeaders headers;
    
    private JwtValidationGatewayFilterFactory filterFactory;
    
    @BeforeEach
    void setUp() {
        when(webClientBuilder.baseUrl(anyString()))
            .thenReturn(webClientBuilder);
        when(webClientBuilder.build()).thenReturn(webClient);
        
        filterFactory = new JwtValidationGatewayFilterFactory(
            webClientBuilder,
            "http://auth-service:4005"
        );
        
        when(exchange.getRequest()).thenReturn(request);
        when(exchange.getResponse()).thenReturn(response);
        when(request.getHeaders()).thenReturn(headers);
    }
    
    @Test
    void shouldAllowValidToken() {
        // Arrange
        String validToken = "Bearer valid-jwt-token";
        when(headers.getFirst(HttpHeaders.AUTHORIZATION))
            .thenReturn(validToken);
        
        when(webClient.get()).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.uri("/validate"))
            .thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.header(anyString(), anyString()))
            .thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.toBodilessEntity())
            .thenReturn(Mono.just(ResponseEntity.ok().build()));
        
        when(chain.filter(exchange)).thenReturn(Mono.empty());
        
        // Act
        GatewayFilter filter = filterFactory.apply(new Object());
        Mono<Void> result = filter.filter(exchange, chain);
        
        // Assert
        StepVerifier.create(result)
            .verifyComplete();
        
        verify(chain).filter(exchange);
    }
    
    @Test
    void shouldRejectMissingToken() {
        // Arrange
        when(headers.getFirst(HttpHeaders.AUTHORIZATION))
            .thenReturn(null);
        when(response.setStatusCode(HttpStatus.UNAUTHORIZED))
            .thenReturn(true);
        when(response.setComplete()).thenReturn(Mono.empty());
        
        // Act
        GatewayFilter filter = filterFactory.apply(new Object());
        Mono<Void> result = filter.filter(exchange, chain);
        
        // Assert
        StepVerifier.create(result)
            .verifyComplete();
        
        verify(response).setStatusCode(HttpStatus.UNAUTHORIZED);
        verify(chain, never()).filter(exchange);
    }
    
    @Test
    void shouldRejectInvalidTokenFormat() {
        // Arrange
        when(headers.getFirst(HttpHeaders.AUTHORIZATION))
            .thenReturn("InvalidFormat");
        when(response.setStatusCode(HttpStatus.UNAUTHORIZED))
            .thenReturn(true);
        when(response.setComplete()).thenReturn(Mono.empty());
        
        // Act
        GatewayFilter filter = filterFactory.apply(new Object());
        Mono<Void> result = filter.filter(exchange, chain);
        
        // Assert
        StepVerifier.create(result)
            .verifyComplete();
        
        verify(response).setStatusCode(HttpStatus.UNAUTHORIZED);
        verify(chain, never()).filter(exchange);
    }
    
    @Test
    void shouldRejectInvalidToken() {
        // Arrange
        String invalidToken = "Bearer invalid-token";
        when(headers.getFirst(HttpHeaders.AUTHORIZATION))
            .thenReturn(invalidToken);
        
        when(webClient.get()).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.uri("/validate"))
            .thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.header(anyString(), anyString()))
            .thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.toBodilessEntity())
            .thenReturn(Mono.error(
                new WebClientResponseException.Unauthorized(
                    401, "Unauthorized", null, null, null
                )
            ));
        
        // Act
        GatewayFilter filter = filterFactory.apply(new Object());
        Mono<Void> result = filter.filter(exchange, chain);
        
        // Assert
        StepVerifier.create(result)
            .expectError(WebClientResponseException.Unauthorized.class)
            .verify();
        
        verify(chain, never()).filter(exchange);
    }
}
```

---

## 🔍 Integration Testing

### Test with MockWebServer

```java
@SpringBootTest
@AutoConfigureWebTestClient
class ApiGatewayIntegrationTest {
    
    @Autowired
    private WebTestClient webTestClient;
    
    private MockWebServer mockAuthService;
    private MockWebServer mockPatientService;
    
    @BeforeEach
    void setUp() throws IOException {
        mockAuthService = new MockWebServer();
        mockAuthService.start(4005);
        
        mockPatientService = new MockWebServer();
        mockPatientService.start(4000);
    }
    
    @AfterEach
    void tearDown() throws IOException {
        mockAuthService.shutdown();
        mockPatientService.shutdown();
    }
    
    @Test
    void shouldAllowRequestWithValidToken() {
        // Mock auth service validation
        mockAuthService.enqueue(
            new MockResponse()
                .setResponseCode(200)
                .setBody("{\"valid\":true}")
        );
        
        // Mock patient service response
        mockPatientService.enqueue(
            new MockResponse()
                .setResponseCode(200)
                .setBody("{\"id\":123,\"name\":\"John Doe\"}")
                .addHeader("Content-Type", "application/json")
        );
        
        // Test request
        webTestClient.get()
            .uri("/api/patients/123")
            .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$.id").isEqualTo(123)
            .jsonPath("$.name").isEqualTo("John Doe");
    }
    
    @Test
    void shouldRejectRequestWithoutToken() {
        webTestClient.get()
            .uri("/api/patients/123")
            .exchange()
            .expectStatus().isUnauthorized();
        
        // Auth service should not be called
        assertEquals(0, mockAuthService.getRequestCount());
    }
    
    @Test
    void shouldRejectRequestWithInvalidToken() {
        // Mock auth service rejection
        mockAuthService.enqueue(
            new MockResponse()
                .setResponseCode(401)
                .setBody("{\"error\":\"Invalid token\"}")
        );
        
        webTestClient.get()
            .uri("/api/patients/123")
            .header(HttpHeaders.AUTHORIZATION, "Bearer invalid-token")
            .exchange()
            .expectStatus().isUnauthorized();
        
        // Patient service should not be called
        assertEquals(0, mockPatientService.getRequestCount());
    }
    
    @Test
    void shouldAllowPublicEndpointWithoutToken() {
        // Mock patient service response
        mockPatientService.enqueue(
            new MockResponse()
                .setResponseCode(200)
                .setBody("{\"openapi\":\"3.0.0\"}")
        );
        
        webTestClient.get()
            .uri("/api-docs/patients")
            .exchange()
            .expectStatus().isOk();
        
        // Auth service should not be called
        assertEquals(0, mockAuthService.getRequestCount());
    }
}
```

---

## 📊 Performance Optimization

### 1. **Connection Pooling**

```java
@Configuration
public class WebClientConfig {
    
    @Bean
    public WebClient.Builder webClientBuilder() {
        ConnectionProvider provider = ConnectionProvider.builder("auth-pool")
            .maxConnections(100)
            .maxIdleTime(Duration.ofSeconds(20))
            .maxLifeTime(Duration.ofSeconds(60))
            .pendingAcquireTimeout(Duration.ofSeconds(60))
            .evictInBackground(Duration.ofSeconds(120))
            .build();
        
        HttpClient httpClient = HttpClient.create(provider)
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
            .responseTimeout(Duration.ofSeconds(5));
        
        return WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(httpClient));
    }
}
```

### 2. **Token Caching**

```java
@Component
public class CachedJwtValidationFilter 
    extends AbstractGatewayFilterFactory<Object> {
    
    private final WebClient webClient;
    private final LoadingCache<String, Boolean> tokenCache;
    
    public CachedJwtValidationFilter(
        WebClient.Builder webClientBuilder,
        @Value("${auth.service.url}") String authServiceUrl
    ) {
        this.webClient = webClientBuilder.baseUrl(authServiceUrl).build();
        this.tokenCache = Caffeine.newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .maximumSize(10_000)
            .build(this::validateTokenWithService);
    }
    
    private Boolean validateTokenWithService(String token) {
        return webClient.get()
            .uri("/validate")
            .header(HttpHeaders.AUTHORIZATION, token)
            .retrieve()
            .toBodilessEntity()
            .map(response -> true)
            .onErrorReturn(false)
            .block();
    }
    
    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            String token = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);
            
            if (token == null || !token.startsWith("Bearer ")) {
                exchange.getResponse()
                    .setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
            
            // Check cache first
            return Mono.fromCallable(() -> tokenCache.get(token))
                .flatMap(valid -> {
                    if (!valid) {
                        exchange.getResponse()
                            .setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }
                    return chain.filter(exchange);
                });
        };
    }
}
```

### 3. **Circuit Breaker Pattern**

```java
@Component
public class ResilientJwtValidationFilter 
    extends AbstractGatewayFilterFactory<Object> {
    
    private final WebClient webClient;
    private final CircuitBreaker circuitBreaker;
    
    public ResilientJwtValidationFilter(
        WebClient.Builder webClientBuilder,
        @Value("${auth.service.url}") String authServiceUrl,
        CircuitBreakerFactory circuitBreakerFactory
    ) {
        this.webClient = webClientBuilder.baseUrl(authServiceUrl).build();
        this.circuitBreaker = circuitBreakerFactory.create("authService");
    }
    
    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> {
            String token = extractToken(exchange);
            
            if (token == null) {
                return unauthorized(exchange);
            }
            
            return Mono.fromSupplier(() -> 
                circuitBreaker.run(
                    () -> validateToken(token),
                    throwable -> handleAuthServiceError(throwable)
                )
            ).flatMap(valid -> {
                if (!valid) {
                    return unauthorized(exchange);
                }
                return chain.filter(exchange);
            });
        };
    }
    
    private Boolean validateToken(String token) {
        return webClient.get()
            .uri("/validate")
            .header(HttpHeaders.AUTHORIZATION, token)
            .retrieve()
            .toBodilessEntity()
            .map(response -> true)
            .onErrorReturn(false)
            .block();
    }
    
    private Boolean handleAuthServiceError(Throwable throwable) {
        log.error("Auth service unavailable, denying access", throwable);
        return false;  // Fail closed - deny access if auth service is down
    }
}
```

---

## 🚀 Production Deployment Checklist

### Configuration

- [ ] Set `auth.service.url` to production auth service
- [ ] Configure connection timeouts appropriately
- [ ] Enable connection pooling
- [ ] Set up circuit breaker with proper thresholds
- [ ] Configure retry logic with exponential backoff
- [ ] Enable request/response logging (with PII masking)

### Security

- [ ] Use HTTPS for all services
- [ ] Validate SSL certificates
- [ ] Implement rate limiting per user/IP
- [ ] Set up token blacklist mechanism
- [ ] Configure CORS properly
- [ ] Remove sensitive data from logs
- [ ] Implement request ID tracking

### Monitoring

- [ ] Set up health checks
- [ ] Monitor auth service latency
- [ ] Track authentication success/failure rates
- [ ] Alert on high error rates
- [ ] Monitor circuit breaker state
- [ ] Track token cache hit/miss rates
- [ ] Set up distributed tracing

### Testing

- [ ] Load test authentication flow
- [ ] Test with expired tokens
- [ ] Test auth service failure scenarios
- [ ] Verify rate limiting works
- [ ] Test concurrent requests
- [ ] Verify token caching works correctly

---

## 🎓 Key Takeaways

### Core Concepts

1. **ServerWebExchange** = Request + Response container
   - Access request data: headers, path, method, body
   - Modify response: status, headers, body
   - Store attributes for downstream filters

2. **GatewayFilterChain** = Linked list of filters
   - `chain.filter(exchange)` = proceed to next filter
   - Not calling chain = stop processing
   - Allows pre and post-processing

3. **Reactive Programming** = Non-blocking operations
   - `Mono<Void>` = 0 or 1 element (completion signal)
   - `.then()` = wait for previous, execute next
   - `.flatMap()` = transform and chain operations
   - No blocking calls in filters!

4. **Custom Filter Factory** = Reusable filter logic
   - Extends `AbstractGatewayFilterFactory`
   - Returns `GatewayFilter` from `apply()` method
   - Can accept configuration via generics

### Authentication Flow

```
1. Extract token from Authorization header
2. Validate token format (Bearer ...)
3. Call auth service to verify token
4. If valid → continue to backend
5. If invalid → return 401
6. Handle errors gracefully
```

### Best Practices

- ✅ Always validate token format before external calls
- ✅ Use reactive programming (no blocking!)
- ✅ Implement proper error handling
- ✅ Cache validation results when appropriate
- ✅ Use circuit breakers for resilience
- ✅ Log with context (request IDs, user IDs)
- ✅ Monitor performance and errors
- ✅ Test all failure scenarios
- ✅ Never log full token values
- ✅ Fail closed (deny access on errors)

---

## 📚 Additional Resources

- **Spring Cloud Gateway Documentation:** https://docs.spring.io/spring-cloud-gateway/docs/current/reference/html/
- **Project Reactor Documentation:** https://projectreactor.io/docs
- **JWT Introduction:** https://jwt.io/introduction
- **WebFlux Documentation:** https://docs.spring.io/spring-framework/docs/current/reference/html/web-reactive.html

---

*Last Updated: November 2025*