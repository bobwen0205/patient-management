# Spring Cloud Gateway - Rate Limiting Implementation Guide

## 📋 Overview

This guide explains how Spring Cloud Gateway implements rate limiting using Redis to prevent API abuse and ensure fair resource usage across all clients. Rate limiting restricts the number of requests a client can make within a specified time window.

**Architecture Pattern:**
```
Client Request → API Gateway → Rate Limiter Check → Redis
                      ↓              ↓
                  [Filter]    [Check Quota]
                      ↓              ↓
                  Allow/Deny    [Update Counter]
```

---

## 🎯 What is Rate Limiting?

Rate limiting controls the rate at which clients can make requests to your API. Common use cases:

- **Prevent abuse**: Stop malicious users from overwhelming your API
- **Ensure fair usage**: Distribute resources fairly among all clients
- **Protect backend services**: Prevent overload and maintain performance
- **Cost control**: Limit external API calls that incur costs
- **SLA enforcement**: Enforce different rate limits for different subscription tiers

**Example Scenarios:**

```
Free Tier:    100 requests/minute
Standard:     1,000 requests/minute
Premium:      10,000 requests/minute
```

---

## 🏗️ Rate Limiting Flow

### Complete Request Flow

```
1. Client makes request
   ↓
2. Request hits API Gateway
   ↓
3. RequestRateLimiter filter intercepts request
   ↓
4. KeyResolver identifies client (by IP, user ID, etc.)
   ↓
5. Check Redis for current request count
   ↓
6. If under limit:
   - Increment counter in Redis
   - Allow request to proceed
   If over limit:
   - Return 429 Too Many Requests
   - Block request
   ↓
7. Response returns to client
```

---

## 📁 Project Structure

```
api-gateway/
├── src/main/java/com/pm/apigateway/
│   └── config/
│       └── RateLimiterConfig.java          ← Key Resolver Configuration
└── src/main/resources/
    └── application.yml                     ← Rate Limit Configuration
```

---

## 🔧 Implementation Components

### 1. **Dependencies (pom.xml)**

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis-reactive</artifactId>
</dependency>
```

**What this provides:**
- Redis reactive client for non-blocking operations
- Integration with Spring Cloud Gateway's reactive architecture
- Support for Redis data structures used by rate limiter
- Connection pooling and management

**Why Redis?**
- **Fast**: In-memory data store with microsecond response times
- **Atomic operations**: INCR, DECR operations are atomic (thread-safe)
- **Expiration**: Built-in TTL (Time To Live) for automatic cleanup
- **Distributed**: Multiple gateway instances can share rate limit state
- **Scalable**: Handles millions of operations per second

---

### 2. **Redis Configuration (application.yml)**

```yaml
spring:
  data:
    redis:
      host: ${REDIS_HOST:redis}
      port: ${REDIS_PORT:6379}
```

**Configuration Breakdown:**

#### `host: ${REDIS_HOST:redis}`
- **Environment variable**: `REDIS_HOST`
- **Default value**: `redis` (Docker service name)
- **Purpose**: Connection endpoint for Redis server
- **Examples**:
  - Docker Compose: `redis` (service name)
  - Local development: `localhost`
  - AWS ElastiCache: `my-cache.abc123.0001.use1.cache.amazonaws.com`

#### `port: ${REDIS_PORT:6379}`
- **Environment variable**: `REDIS_PORT`
- **Default value**: `6379` (standard Redis port)
- **Purpose**: TCP port for Redis connection

**Connection Example:**
```
Gateway connects to: redis:6379
Full connection string: redis://redis:6379
```

---

### 3. **RateLimiterConfig.java - Key Resolver**

```java
@Configuration
public class RateLimiterConfig {

    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange ->
                Mono.just(exchange.getRequest().getRemoteAddress().getAddress().getHostAddress());
    }
}
```

#### Complete Breakdown

**@Configuration**
```java
@Configuration
```
- Marks class as Spring configuration
- Contains bean definitions
- Loaded during application startup
- Makes beans available for dependency injection

---

**@Bean**
```java
@Bean
public KeyResolver ipKeyResolver() {
```
- Defines a Spring bean of type `KeyResolver`
- Bean name: `ipKeyResolver` (method name)
- Used by rate limiter to identify clients
- Singleton scope (one instance for entire application)

---

**KeyResolver Interface**
```java
public KeyResolver ipKeyResolver() {
    return exchange -> ...
}
```

`KeyResolver` is a functional interface with one method:
```java
@FunctionalInterface
public interface KeyResolver {
    Mono<String> resolve(ServerWebExchange exchange);
}
```

**Purpose**: Extract a unique identifier (key) from each request
- Input: `ServerWebExchange` (current HTTP request)
- Output: `Mono<String>` (unique identifier for rate limiting)

**Lambda Expression:**
```java
exchange -> Mono.just(...)
```
- `exchange`: Current HTTP request/response
- `Mono.just(...)`: Wraps result in reactive container
- Returns immediately (non-blocking)

---

**Extract Client IP Address**

```java
exchange.getRequest().getRemoteAddress().getAddress().getHostAddress()
```

Let's break this down step by step:

#### Step 1: `exchange.getRequest()`
```java
ServerHttpRequest request = exchange.getRequest();
```
- Returns the HTTP request object
- Contains headers, path, method, remote address, etc.

#### Step 2: `.getRemoteAddress()`
```java
InetSocketAddress remoteAddress = request.getRemoteAddress();
```
- Returns client's network address
- Type: `InetSocketAddress` (IP address + port)
- Example: `192.168.1.100:54321`

**Structure of InetSocketAddress:**
```
InetSocketAddress
├── InetAddress getAddress()    ← IP address object
└── int getPort()                ← Port number (54321)
```

#### Step 3: `.getAddress()`
```java
InetAddress address = remoteAddress.getAddress();
```
- Extracts just the IP address part
- Type: `InetAddress` (abstract class)
- Ignores port number
- Example: `192.168.1.100`

**InetAddress Class Hierarchy:**
```
InetAddress (abstract)
├── Inet4Address (IPv4: 192.168.1.100)
└── Inet6Address (IPv6: 2001:0db8:85a3::8a2e:0370:7334)
```

#### Step 4: `.getHostAddress()`
```java
String ipAddress = address.getHostAddress();
```
- Converts InetAddress to String
- Returns human-readable IP address
- IPv4: `"192.168.1.100"`
- IPv6: `"2001:0db8:85a3::8a2e:0370:7334"`

---

**Complete Flow Example:**

```java
// Example request from client at 203.0.113.45:52341

ServerWebExchange exchange = ... // Current request

// Step 1: Get request
ServerHttpRequest request = exchange.getRequest();
// request = ServerHttpRequest object

// Step 2: Get remote address
InetSocketAddress remoteAddress = request.getRemoteAddress();
// remoteAddress = 203.0.113.45:52341

// Step 3: Get address (without port)
InetAddress address = remoteAddress.getAddress();
// address = InetAddress[203.0.113.45]

// Step 4: Convert to string
String ipAddress = address.getHostAddress();
// ipAddress = "203.0.113.45"

// Wrap in Mono
Mono<String> key = Mono.just(ipAddress);
// key = Mono["203.0.113.45"]
```

---

**Why IP-Based Rate Limiting?**

✅ **Advantages:**
- Simple to implement
- No authentication required
- Works for public APIs
- Prevents DDoS attacks

❌ **Limitations:**
- Multiple users behind same NAT share limit
- Dynamic IPs can bypass limits
- VPN/proxy can change IPs
- Not suitable for user-specific quotas

---

### 4. **Alternative Key Resolvers**

#### User ID Based (Requires Authentication)
```java
@Bean
public KeyResolver userKeyResolver() {
    return exchange -> exchange.getPrincipal()
            .map(Principal::getName)
            .defaultIfEmpty("anonymous");
}
```

**How it works:**
1. Extracts authenticated user from JWT token
2. Uses username/user ID as rate limit key
3. Each user gets independent rate limit
4. Requires authentication filter before rate limiter

**Use case:**
```
User A: 100 requests/minute
User B: 100 requests/minute
User C: 100 requests/minute
(Each user has separate quota)
```

---

#### API Key Based
```java
@Bean
public KeyResolver apiKeyResolver() {
    return exchange -> {
        String apiKey = exchange.getRequest()
                .getHeaders()
                .getFirst("X-API-Key");
        
        return Mono.justOrEmpty(apiKey)
                .defaultIfEmpty("missing-api-key");
    };
}
```

**How it works:**
1. Extracts API key from custom header
2. Uses API key as rate limit key
3. Different keys = different quotas
4. Common for B2B APIs

**Request Example:**
```http
GET /api/patients HTTP/1.1
X-API-Key: sk_live_abc123def456
```

---

#### Combined Key (IP + Path)
```java
@Bean
public KeyResolver combinedKeyResolver() {
    return exchange -> {
        String ip = exchange.getRequest()
                .getRemoteAddress()
                .getAddress()
                .getHostAddress();
        
        String path = exchange.getRequest()
                .getPath()
                .value();
        
        return Mono.just(ip + ":" + path);
    };
}
```

**How it works:**
1. Combines IP address with request path
2. Different endpoints have separate limits
3. Same IP, different paths = different quotas

**Example keys:**
```
192.168.1.100:/api/patients    → 100 req/min
192.168.1.100:/api/doctors     → 100 req/min
192.168.1.100:/auth/login      → 10 req/min
```

**Use case:** Different rate limits for different endpoints

---

#### JWT Subject Based
```java
@Bean
public KeyResolver jwtSubjectResolver() {
    return exchange -> {
        String token = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);
        
        if (token != null && token.startsWith("Bearer ")) {
            String jwt = token.substring(7);
            // Extract subject from JWT
            String subject = extractSubject(jwt);
            return Mono.just(subject);
        }
        
        return Mono.just("anonymous");
    };
}
```

---

### 5. **Rate Limiter Configuration (application.yml)**

```yaml
spring:
  cloud:
    gateway:
      default-filters:
        - name: RequestRateLimiter
          args:
            redis-rate-limiter.burstCapacity: 5
            redis-rate-limiter.replenishRate: 5
            key-resolver: "#{@ipKeyResolver}"
```

#### Configuration Breakdown

**default-filters:**
```yaml
default-filters:
  - name: RequestRateLimiter
```
- Applies to ALL routes automatically
- No need to specify in each route
- Alternative: per-route configuration

---

**name: RequestRateLimiter**
```yaml
- name: RequestRateLimiter
```
- Built-in Spring Cloud Gateway filter
- Uses Token Bucket algorithm
- Requires Redis for distributed state
- Reactive implementation (non-blocking)

---

**redis-rate-limiter.replenishRate: 5**
```yaml
redis-rate-limiter.replenishRate: 5
```

**What it means:**
- **5 requests per second** are allowed
- Tokens are added to bucket at this rate
- Steady-state throughput limit
- Sustained request rate over time

**Calculation:**
```
5 requests/second = 300 requests/minute = 18,000 requests/hour
```

**How it works:**
```
Second 0: Bucket has 5 tokens → 5 requests allowed
Second 1: Bucket refills +5 tokens → 5 more requests allowed
Second 2: Bucket refills +5 tokens → 5 more requests allowed
...
```

**Token replenishment is continuous:**
- Every 200ms: +1 token added
- Every 1000ms: +5 tokens added
- Rate is constant and predictable

---

**redis-rate-limiter.burstCapacity: 5**
```yaml
redis-rate-limiter.burstCapacity: 5
```

**What it means:**
- **Maximum 5 requests** can be made instantly
- Maximum tokens bucket can hold
- Allows handling traffic spikes
- Bucket capacity limit

**Burst Scenarios:**

**Scenario 1: Small bursts within capacity**
```
Time 0.0s: Client sends 3 requests → All allowed (5-3=2 tokens left)
Time 0.5s: Client sends 2 requests → All allowed (2-2=0 tokens left)
Time 1.0s: Bucket refills to 5 tokens
Time 1.0s: Client sends 5 requests → All allowed
```

**Scenario 2: Burst exceeds capacity**
```
Time 0.0s: Client sends 8 requests
           → First 5 allowed (bucket empty)
           → Remaining 3 rejected (429 Too Many Requests)
```

**Scenario 3: Long idle period**
```
Time 0.0s: Bucket has 5 tokens
Time 10.0s: No requests (bucket stays at 5, doesn't exceed)
Time 10.0s: Client sends 5 requests → All allowed
```

---

**Token Bucket Algorithm**

```
Token Bucket
├── Capacity: Maximum tokens (burstCapacity)
├── Current: Tokens available now
├── Refill Rate: Tokens added per second (replenishRate)
└── Request Cost: Tokens per request (usually 1)

Request Processing:
1. Check if bucket has ≥1 token
2. If yes: Take 1 token, allow request
3. If no: Reject request (429)
4. Continuously refill at replenishRate
```

**Visual Example:**

```
Bucket Capacity: 5 tokens
Refill Rate: 5 tokens/second (1 token every 200ms)

Time: 0.0s
Bucket: [●●●●●] (5 tokens)
Request 1: ✅ Allowed
Bucket: [●●●●○] (4 tokens)

Request 2: ✅ Allowed
Bucket: [●●●○○] (3 tokens)

Request 3: ✅ Allowed
Bucket: [●●○○○] (2 tokens)

Request 4: ✅ Allowed
Bucket: [●○○○○] (1 token)

Request 5: ✅ Allowed
Bucket: [○○○○○] (0 tokens)

Request 6: ❌ REJECTED (429 Too Many Requests)
Bucket: [○○○○○] (0 tokens)

Time: 0.2s (200ms later)
Bucket: [●○○○○] (1 token refilled)
Request 7: ✅ Allowed
Bucket: [○○○○○] (0 tokens)

Time: 0.4s (400ms from start)
Bucket: [●○○○○] (1 token refilled)

Time: 1.0s (1 second from start)
Bucket: [●●●●●] (5 tokens, fully refilled)
```

---

**key-resolver: "#{@ipKeyResolver}"**
```yaml
key-resolver: "#{@ipKeyResolver}"
```

**Spring Expression Language (SpEL):**
- `#{}`: SpEL syntax for runtime evaluation
- `@ipKeyResolver`: Reference to Spring bean by name
- Looks up bean from application context
- Connects rate limiter to key resolver

**How it works:**
```java
// 1. Spring creates bean from config
@Bean
public KeyResolver ipKeyResolver() { ... }

// 2. YAML references bean by name
key-resolver: "#{@ipKeyResolver}"

// 3. Rate limiter uses this bean at runtime
String key = ipKeyResolver.resolve(exchange).block();
```

**Alternative bean references:**
```yaml
# Reference by name
key-resolver: "#{@ipKeyResolver}"

# Reference by type (if only one KeyResolver exists)
key-resolver: "#{@keyResolver}"

# Reference user resolver
key-resolver: "#{@userKeyResolver}"

# Reference API key resolver
key-resolver: "#{@apiKeyResolver}"
```

---

## 🔍 How Redis Stores Rate Limit Data

### Redis Data Structure

Spring Cloud Gateway uses Redis to store rate limit counters with the following pattern:

**Key Format:**
```
request_rate_limiter.{key}.tokens
request_rate_limiter.{key}.timestamp
```

**Example for IP 192.168.1.100:**
```
request_rate_limiter.192.168.1.100.tokens → "3"
request_rate_limiter.192.168.1.100.timestamp → "1699459200"
```

---

### Redis Operations

**When Request Arrives:**

```lua
-- Pseudo-code of Redis operations
local tokens_key = "request_rate_limiter." .. key .. ".tokens"
local timestamp_key = "request_rate_limiter." .. key .. ".timestamp"

-- Get current values
local tokens = redis.call('GET', tokens_key)
local last_timestamp = redis.call('GET', timestamp_key)
local now = current_time()

-- Calculate tokens to add based on time elapsed
local time_elapsed = now - last_timestamp
local tokens_to_add = time_elapsed * replenishRate

-- Update token count
local new_tokens = math.min(tokens + tokens_to_add, burstCapacity)

-- Check if request can proceed
if new_tokens >= 1 then
    -- Allow request
    redis.call('SET', tokens_key, new_tokens - 1)
    redis.call('SET', timestamp_key, now)
    return true
else
    -- Reject request
    return false
end
```

---

### Redis Commands in Action

**Initial State (No requests yet):**
```redis
> GET request_rate_limiter.192.168.1.100.tokens
(nil)

> GET request_rate_limiter.192.168.1.100.timestamp
(nil)
```

**After First Request:**
```redis
> GET request_rate_limiter.192.168.1.100.tokens
"4"  # Started with 5, used 1

> GET request_rate_limiter.192.168.1.100.timestamp
"1699459200"  # Unix timestamp
```

**After 5 Quick Requests:**
```redis
> GET request_rate_limiter.192.168.1.100.tokens
"0"  # Bucket empty

# 6th request would be rejected
```

**After 1 Second (Refill):**
```redis
> GET request_rate_limiter.192.168.1.100.tokens
"5"  # Refilled to capacity
```

---

### Distributed Rate Limiting

**Why Redis is Essential for Multiple Gateway Instances:**

```
          Client
             ↓
    ┌────────┴────────┐
    ↓                 ↓
Gateway 1        Gateway 2
    ↓                 ↓
    └────────┬────────┘
             ↓
           Redis
    (Shared State)
```

**Without Redis (Each gateway has own memory):**
```
Client → Gateway 1: 5 requests ✅
Client → Gateway 2: 5 requests ✅
Total: 10 requests (limit bypassed!)
```

**With Redis (Shared state across gateways):**
```
Client → Gateway 1: 5 requests ✅ (Redis: 5 tokens used)
Client → Gateway 2: 0 requests ❌ (Redis: no tokens left)
Total: 5 requests (limit enforced!)
```

---

## 🎯 Complete Rate Limiting Flow

### Step-by-Step Request Processing

```
┌─────────────────────────────────────────────────────────────┐
│  1. Client Request                                          │
│     GET /api/patients                                       │
│     X-Forwarded-For: 192.168.1.100                         │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│  2. API Gateway Receives Request                            │
│     - Creates ServerWebExchange                             │
│     - Starts filter chain processing                        │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│  3. RequestRateLimiter Filter Triggered                     │
│     - First filter in default-filters chain                 │
│     - Intercepts ALL requests                               │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│  4. Key Resolution (ipKeyResolver)                          │
│     exchange.getRequest()                                   │
│         .getRemoteAddress()                                 │
│         .getAddress()                                       │
│         .getHostAddress()                                   │
│                                                             │
│     Result: "192.168.1.100"                                │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│  5. Redis Lookup                                            │
│     GET request_rate_limiter.192.168.1.100.tokens          │
│     GET request_rate_limiter.192.168.1.100.timestamp       │
│                                                             │
│     Current tokens: 3                                       │
│     Last timestamp: 1699459200                              │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│  6. Token Bucket Algorithm                                  │
│                                                             │
│     a) Calculate elapsed time                               │
│        now = 1699459201                                     │
│        elapsed = now - last_timestamp = 1 second            │
│                                                             │
│     b) Calculate tokens to add                              │
│        tokens_to_add = elapsed × replenishRate              │
│        tokens_to_add = 1 × 5 = 5 tokens                     │
│                                                             │
│     c) Update token count                                   │
│        new_tokens = min(3 + 5, 5) = 5 tokens               │
│        (capped at burstCapacity)                            │
│                                                             │
│     d) Check availability                                   │
│        if new_tokens >= 1:                                  │
│            allow_request = true                             │
│            remaining_tokens = 5 - 1 = 4                     │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│  7. Update Redis                                            │
│     SET request_rate_limiter.192.168.1.100.tokens "4"      │
│     SET request_rate_limiter.192.168.1.100.timestamp "..."  │
│                                                             │
│     Expiration: 2 × burstCapacity / replenishRate           │
│     TTL: 2 × 5 / 5 = 2 seconds (cleanup old data)          │
└────────────────────┬────────────────────────────────────────┘
                     ↓
           ┌─────────┴─────────┐
           ↓                   ↓
    ✅ ALLOWED          ❌ REJECTED
           ↓                   ↓
┌──────────────────┐  ┌──────────────────┐
│ 8a. Continue     │  │ 8b. Return 429   │
│     Chain        │  │                  │
│                  │  │ HTTP/1.1 429     │
│ - JwtValidation  │  │ X-RateLimit:     │
│ - Route to       │  │   Exceeded       │
│   backend        │  │                  │
└──────────────────┘  └──────────────────┘
           ↓
┌──────────────────┐
│ 9. Response      │
│                  │
│ HTTP/1.1 200 OK  │
│ X-RateLimit-     │
│   Remaining: 4   │
└──────────────────┘
```

---

## 📊 Rate Limit Headers

Spring Cloud Gateway automatically adds these headers to responses:

```http
X-RateLimit-Remaining: 4
X-RateLimit-Requested-Tokens: 1
X-RateLimit-Burst-Capacity: 5
X-RateLimit-Replenish-Rate: 5
```

**Header Explanations:**

### X-RateLimit-Remaining: 4
- Tokens left in bucket after this request
- Client can make 4 more immediate requests
- Helps clients implement backoff strategies

### X-RateLimit-Requested-Tokens: 1
- Number of tokens consumed by this request
- Usually 1, but can be configured differently
- Advanced: Expensive operations could cost more tokens

### X-RateLimit-Burst-Capacity: 5
- Maximum requests allowed instantly
- Bucket capacity
- Informs client of burst limits

### X-RateLimit-Replenish-Rate: 5
- Tokens added per second
- Sustained request rate
- Tells client when more requests will be available

---

## 🚨 Error Response (429 Too Many Requests)

**When Limit Exceeded:**

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
X-RateLimit-Remaining: 0
X-RateLimit-Burst-Capacity: 5
X-RateLimit-Replenish-Rate: 5

{
  "status": 429,
  "error": "Too Many Requests",
  "message": "You have exhausted your API Request Quota"
}
```

**Client Should:**
1. Stop sending requests immediately
2. Check `X-RateLimit-Remaining` header
3. Calculate wait time: `1 / replenishRate` seconds
4. Implement exponential backoff
5. Retry after appropriate delay

---

## 🔄 Per-Route Rate Limiting

Instead of `default-filters`, you can apply rate limiting per route:

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: patient-service-route
          uri: http://patient-service:4000
          predicates:
            - Path=/api/patients/**
          filters:
            - name: RequestRateLimiter
              args:
                redis-rate-limiter.replenishRate: 10
                redis-rate-limiter.burstCapacity: 20
                key-resolver: "#{@ipKeyResolver}"
        
        - id: auth-service-route
          uri: http://auth-service:4005
          predicates:
            - Path=/auth/**
          filters:
            - name: RequestRateLimiter
              args:
                redis-rate-limiter.replenishRate: 2
                redis-rate-limiter.burstCapacity: 5
                key-resolver: "#{@ipKeyResolver}"
```

**Different limits for different routes:**
```
/api/patients/** → 10 req/sec, burst 20
/auth/**         → 2 req/sec, burst 5 (login protection)
```

---

## 🧪 Testing Rate Limiting

### Manual Testing with cURL

**Test 1: Send requests within limit**
```bash
# Send 5 requests (should all succeed)
for i in {1..5}; do
  curl -i http://localhost:4004/api/patients
done

# All return 200 OK
# Check X-RateLimit-Remaining header
```

**Test 2: Exceed rate limit**
```bash
# Send 10 requests quickly
for i in {1..10}; do
  curl -i http://localhost:4004/api/patients
done

# First 5: 200 OK
# Remaining 5: 429 Too Many Requests
```

**Test 3: Wait and retry**
```bash
# Send 5 requests
for i in {1..5}; do
  curl -i http://localhost:4004/api/patients
done

# Wait 1 second (for tokens to refill)
sleep 1

# Send 5 more requests (should succeed)
for i in {1..5}; do
  curl -i http://localhost:4004/api/patients
done
```

---

### Automated Testing

**Test with Apache Bench:**
```bash
# 100 requests, 10 concurrent
ab -n 100 -c 10 http://localhost:4004/api/patients

# Check how many returned 429
```

**Test with JMeter:**
1. Create Thread Group: 50 users
2. Ramp-up: 1 second
3. Loop: 5 times
4. Add assertions for 200/429 responses
5. View Results Tree to see rate limiting in action

---

## 📈 Monitoring and Metrics

### Key Metrics to Track

1. **Total Requests**: Total API traffic
2. **Rate Limited Requests**: Count of 429 responses
3. **Rate Limit Hit Rate**: `429s / Total Requests × 100%`
4. **Per-IP Request Rates**: Identify abusers
5. **Average Response Time**: Check Redis performance
6. **Redis Connection Pool**: Monitor Redis health

### Example Monitoring Query (Prometheus)

```promql
# Rate limit rejections per second
rate(http_server_requests_total{status="429"}[1m])

# Rate limit hit rate
rate(http_server_requests_total{status="429"}[5m]) 
/ 
rate(http_server_requests_total[5m]) * 100
```

---

## 🎓 Configuration Examples

### Conservative (Strict Limits)
```yaml
redis-rate-limiter.replenishRate: 1    # 1 req/sec
redis-rate-limiter.burstCapacity: 5    # 5 burst
# Use for: Login endpoints, expensive operations
```

### Moderate (Balanced)
```yaml
redis-rate-limiter.replenishRate: 10   # 10 req/sec
redis-rate-limiter.burstCapacity: 20   # 20 burst
# Use for: Standard API endpoints
```

### Permissive (High Traffic)
```yaml
redis-rate-limiter.replenishRate: 100  # 100 req/sec
redis-rate-limiter.burstCapacity: 200  # 200 burst
# Use for: Read-only operations, health checks
```

### Tiered (Based on Subscription Level)
```java
@Configuration
public class TieredRateLimiterConfig {
    
    @Bean
    public KeyResolver tieredKeyResolver() {
        return exchange -> {
            String apiKey = exchange.getRequest()
                    .getHeaders()
                    .getFirst("X-API-Key");
            
            // Determine tier from API key
            String tier = determineTier(apiKey);
            
            // Combine IP with tier for unique key
            String ip = exchange.getRequest()
                    .getRemoteAddress()
                    .getAddress()
                    .getHostAddress();
            
            return Mono.just(tier + ":" + ip);
        };
    }
    
    private String determineTier(String apiKey) {
        if (apiKey == null) return "free";
        if (apiKey.startsWith("premium_")) return "premium";
        if (apiKey.startsWith("standard_")) return "standard";
        return "free";
    }
}
```

**YAML Configuration:**
```yaml
routes:
  - id: free-tier-route
    uri: http://service:4000
    predicates:
      - Path=/api/**
      - Header=X-API-Key, free_.*
    filters:
      - name: RequestRateLimiter
        args:
          redis-rate-limiter.replenishRate: 1
          redis-rate-limiter.burstCapacity: 5
          key-resolver: "#{@tieredKeyResolver}"
  
  - id: standard-tier-route
    uri: http://service:4000
    predicates:
      - Path=/api/**
      - Header=X-API-Key, standard_.*
    filters:
      - name: RequestRateLimiter
        args:
          redis-rate-limiter.replenishRate: 10
          redis-rate-limiter.burstCapacity: 20
          key-resolver: "#{@tieredKeyResolver}"
  
  - id: premium-tier-route
    uri: http://service:4000
    predicates:
      - Path=/api/**
      - Header=X-API-Key, premium_.*
    filters:
      - name: RequestRateLimiter
        args:
          redis-rate-limiter.replenishRate: 100
          redis-rate-limiter.burstCapacity: 200
          key-resolver: "#{@tieredKeyResolver}"
```

**Result:**
```
Free:     1 req/sec, burst 5
Standard: 10 req/sec, burst 20
Premium:  100 req/sec, burst 200
```

---

## 🔧 Advanced Rate Limiting Patterns

### 1. **Custom Rate Limiter with User Quotas**

```java
@Component
public class QuotaBasedRateLimiter implements RateLimiter<Object> {
    
    private final RedisTemplate<String, String> redisTemplate;
    private final UserQuotaService quotaService;
    
    @Override
    public Mono<Response> isAllowed(String routeId, String id) {
        String key = "quota:" + id;
        
        return Mono.fromCallable(() -> {
            // Get user's quota (daily limit)
            int dailyLimit = quotaService.getDailyLimit(id);
            
            // Get current usage from Redis
            String usageStr = redisTemplate.opsForValue().get(key);
            int currentUsage = usageStr != null ? Integer.parseInt(usageStr) : 0;
            
            if (currentUsage >= dailyLimit) {
                // Quota exceeded
                return new Response(false, getHeaders(dailyLimit, 0));
            }
            
            // Increment usage
            redisTemplate.opsForValue().increment(key);
            
            // Set expiration at midnight
            LocalDateTime midnight = LocalDateTime.now()
                    .plusDays(1)
                    .withHour(0)
                    .withMinute(0)
                    .withSecond(0);
            Duration ttl = Duration.between(LocalDateTime.now(), midnight);
            redisTemplate.expire(key, ttl.getSeconds(), TimeUnit.SECONDS);
            
            int remaining = dailyLimit - currentUsage - 1;
            return new Response(true, getHeaders(dailyLimit, remaining));
        });
    }
    
    private Map<String, String> getHeaders(int limit, int remaining) {
        Map<String, String> headers = new HashMap<>();
        headers.put("X-RateLimit-Limit", String.valueOf(limit));
        headers.put("X-RateLimit-Remaining", String.valueOf(remaining));
        return headers;
    }
}
```

**Usage:**
```yaml
filters:
  - name: RequestRateLimiter
    args:
      rate-limiter: "#{@quotaBasedRateLimiter}"
      key-resolver: "#{@userKeyResolver}"
```

---

### 2. **Weighted Rate Limiting (Different Costs for Operations)**

```java
@Component
public class WeightedRateLimiterConfig {
    
    @Bean
    public RateLimiter<WeightedConfig> weightedRateLimiter() {
        return (routeId, id) -> {
            // Different operations cost different tokens
            int cost = determineRequestCost(routeId);
            
            return redisRateLimiter.isAllowed(routeId, id)
                    .map(response -> {
                        if (response.isAllowed()) {
                            // Deduct additional tokens for expensive ops
                            deductTokens(id, cost - 1);
                        }
                        return response;
                    });
        };
    }
    
    private int determineRequestCost(String routeId) {
        // Define costs per route
        return switch (routeId) {
            case "search-route" -> 5;        // Expensive
            case "report-route" -> 10;       // Very expensive
            case "read-route" -> 1;          // Cheap
            default -> 1;
        };
    }
}
```

**Cost Examples:**
```
GET /api/patients/123          → 1 token
GET /api/patients/search       → 5 tokens
POST /api/reports/generate     → 10 tokens
GET /health                    → 1 token
```

---

### 3. **Time-Based Rate Limiting (Different Limits by Time of Day)**

```java
@Bean
public KeyResolver timeBasedKeyResolver() {
    return exchange -> {
        String ip = exchange.getRequest()
                .getRemoteAddress()
                .getAddress()
                .getHostAddress();
        
        int hour = LocalDateTime.now().getHour();
        
        // Peak hours (9 AM - 5 PM): Stricter limits
        // Off-peak: More relaxed
        String timeZone = (hour >= 9 && hour <= 17) ? "peak" : "offpeak";
        
        return Mono.just(timeZone + ":" + ip);
    };
}
```

**YAML:**
```yaml
routes:
  - id: peak-hours
    uri: http://service:4000
    predicates:
      - Path=/api/**
      - Between=09:00,17:00
    filters:
      - name: RequestRateLimiter
        args:
          redis-rate-limiter.replenishRate: 5
          redis-rate-limiter.burstCapacity: 10
          key-resolver: "#{@timeBasedKeyResolver}"
  
  - id: off-peak-hours
    uri: http://service:4000
    predicates:
      - Path=/api/**
    filters:
      - name: RequestRateLimiter
        args:
          redis-rate-limiter.replenishRate: 20
          redis-rate-limiter.burstCapacity: 50
          key-resolver: "#{@timeBasedKeyResolver}"
```

---

### 4. **Circuit Breaker + Rate Limiting**

```yaml
filters:
  - name: RequestRateLimiter
    args:
      redis-rate-limiter.replenishRate: 10
      redis-rate-limiter.burstCapacity: 20
      key-resolver: "#{@ipKeyResolver}"
  
  - name: CircuitBreaker
    args:
      name: backendCircuitBreaker
      fallbackUri: forward:/fallback
      
  - name: Retry
    args:
      retries: 3
      statuses: BAD_GATEWAY,SERVICE_UNAVAILABLE
      methods: GET
      backoff:
        firstBackoff: 50ms
        maxBackoff: 500ms
        factor: 2
```

**Flow:**
```
Request → Rate Limiter → Circuit Breaker → Retry → Backend
   ↓           ↓              ↓              ↓
 429      If allowed    If open        Max 3 tries
          proceed     return 503      with backoff
```

---

## 🐳 Docker Compose Configuration

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    container_name: redis
    ports:
      - "6379:6379"
    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5
    volumes:
      - redis-data:/data
    networks:
      - gateway-network

  api-gateway:
    build: ./api-gateway
    container_name: api-gateway
    ports:
      - "4004:4004"
    environment:
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - SPRING_PROFILES_ACTIVE=prod
    depends_on:
      redis:
        condition: service_healthy
    networks:
      - gateway-network

  patient-service:
    build: ./patient-service
    container_name: patient-service
    ports:
      - "4000:4000"
    networks:
      - gateway-network

  auth-service:
    build: ./auth-service
    container_name: auth-service
    ports:
      - "4005:4005"
    networks:
      - gateway-network

volumes:
  redis-data:

networks:
  gateway-network:
    driver: bridge
```

**Redis Configuration Options:**

### `maxmemory 256mb`
- Maximum memory Redis can use
- Prevents Redis from consuming all server memory
- Adjust based on expected traffic

### `maxmemory-policy allkeys-lru`
- When memory limit reached, evict least recently used keys
- Other options:
  - `allkeys-lfu`: Least frequently used
  - `volatile-lru`: LRU among keys with expiration
  - `volatile-ttl`: Remove keys closest to expiration
  - `noeviction`: Return errors when memory full

---

## 🔍 Debugging Rate Limiting

### Enable Debug Logging

**application.yml:**
```yaml
logging:
  level:
    org.springframework.cloud.gateway: DEBUG
    org.springframework.data.redis: DEBUG
    org.springframework.cloud.gateway.filter.ratelimit: TRACE
```

**Sample Log Output:**
```
DEBUG RequestRateLimiter: Resolved key: 192.168.1.100
TRACE RequestRateLimiter: Checking rate limit for key: 192.168.1.100
DEBUG RedisRateLimiter: Tokens remaining: 4
DEBUG RedisRateLimiter: Request allowed: true
DEBUG RequestRateLimiter: Adding rate limit headers
```

---

### Monitor Redis Keys

**Connect to Redis CLI:**
```bash
docker exec -it redis redis-cli
```

**View all rate limit keys:**
```redis
> KEYS request_rate_limiter.*
1) "request_rate_limiter.192.168.1.100.tokens"
2) "request_rate_limiter.192.168.1.100.timestamp"
3) "request_rate_limiter.10.0.0.5.tokens"
4) "request_rate_limiter.10.0.0.5.timestamp"
```

**Check specific client's tokens:**
```redis
> GET request_rate_limiter.192.168.1.100.tokens
"3"

> GET request_rate_limiter.192.168.1.100.timestamp
"1699459201"
```

**Monitor in real-time:**
```redis
> MONITOR
OK
1699459201.123456 [0 127.0.0.1:54321] "GET" "request_rate_limiter.192.168.1.100.tokens"
1699459201.234567 [0 127.0.0.1:54321] "SET" "request_rate_limiter.192.168.1.100.tokens" "2"
```

**Check memory usage:**
```redis
> INFO memory
used_memory:1048576
used_memory_human:1.00M
used_memory_rss:2097152
used_memory_peak:3145728
```

---

## 🚨 Common Issues and Solutions

### Issue 1: Rate Limiter Not Working

**Symptoms:**
- All requests pass through
- No 429 responses
- No rate limit headers

**Possible Causes:**

**A. Redis not connected**
```bash
# Check logs
docker logs api-gateway | grep -i redis

# Expected: Connection established
# Error: Connection refused
```

**Solution:**
```yaml
# Verify Redis configuration
spring:
  data:
    redis:
      host: redis  # Must match Docker service name
      port: 6379   # Default Redis port
```

**B. KeyResolver returns empty**
```java
// Bad: Returns empty Mono
return Mono.empty();

// Good: Always return a key
return Mono.just("default-key");
```

**C. Filter not applied to route**
```yaml
# Wrong: Filter in wrong place
routes:
  - id: my-route
    filters:
      - StripPrefix=1
    # RequestRateLimiter missing!

# Correct: Add RequestRateLimiter
routes:
  - id: my-route
    filters:
      - name: RequestRateLimiter
        args:
          redis-rate-limiter.replenishRate: 5
          redis-rate-limiter.burstCapacity: 5
          key-resolver: "#{@ipKeyResolver}"
```

---

### Issue 2: All Requests Get 429 Immediately

**Symptoms:**
- First request fails with 429
- No requests ever succeed

**Possible Causes:**

**A. replenishRate or burstCapacity set to 0**
```yaml
# Wrong
redis-rate-limiter.replenishRate: 0
redis-rate-limiter.burstCapacity: 0

# Correct
redis-rate-limiter.replenishRate: 5
redis-rate-limiter.burstCapacity: 5
```

**B. Clock skew between servers**
- Gateway and Redis have different times
- Causes timestamp calculation errors

**Solution:**
```bash
# Sync time on all servers
sudo ntpdate -s time.nist.gov

# Or use NTP service
sudo systemctl enable ntp
sudo systemctl start ntp
```

**C. Redis keys already exist with wrong values**
```redis
# Check current values
> GET request_rate_limiter.192.168.1.100.tokens
"-5"  # Negative! This is wrong

# Delete corrupted keys
> DEL request_rate_limiter.192.168.1.100.tokens
> DEL request_rate_limiter.192.168.1.100.timestamp
```

---

### Issue 3: Rate Limiting Inconsistent Across Gateway Instances

**Symptoms:**
- Sometimes requests go through
- Sometimes they don't
- Behavior unpredictable

**Cause:**
- Multiple gateway instances using different Redis instances
- Or not using Redis at all (in-memory fallback)

**Solution:**
```yaml
# All gateways must point to SAME Redis
spring:
  data:
    redis:
      host: shared-redis.company.com  # Same for all
      port: 6379
```

---

### Issue 4: Redis Memory Full

**Symptoms:**
```redis
> SET test value
(error) OOM command not allowed when used memory > 'maxmemory'
```

**Solutions:**

**A. Increase memory limit**
```bash
# Edit redis.conf
maxmemory 512mb
```

**B. Enable eviction policy**
```bash
maxmemory-policy allkeys-lru
```

**C. Reduce TTL on rate limit keys**
```java
// Shorter TTL = less memory usage
redisTemplate.expire(key, 60, TimeUnit.SECONDS);
```

**D. Monitor and alert**
```bash
# Check memory usage
redis-cli INFO memory | grep used_memory_human

# Set up alerts at 80% usage
```

---

### Issue 5: Performance Degradation

**Symptoms:**
- Slow API responses
- Increased latency
- Redis connection timeouts

**Solutions:**

**A. Increase Redis connection pool**
```yaml
spring:
  data:
    redis:
      lettuce:
        pool:
          max-active: 20
          max-idle: 10
          min-idle: 5
          max-wait: 1000ms
```

**B. Use Redis cluster for high traffic**
```yaml
spring:
  data:
    redis:
      cluster:
        nodes:
          - redis-1:6379
          - redis-2:6379
          - redis-3:6379
```

**C. Optimize key expiration**
```java
// Set appropriate TTL
long ttl = 2 * burstCapacity / replenishRate;
redisTemplate.expire(key, ttl, TimeUnit.SECONDS);
```

---

## 📊 Production Deployment Best Practices

### 1. **Redis High Availability**

**Use Redis Sentinel for automatic failover:**
```yaml
spring:
  data:
    redis:
      sentinel:
        master: mymaster
        nodes:
          - sentinel-1:26379
          - sentinel-2:26379
          - sentinel-3:26379
```

**Or Redis Cluster for scalability:**
```yaml
spring:
  data:
    redis:
      cluster:
        nodes:
          - redis-1:6379
          - redis-2:6379
          - redis-3:6379
          - redis-4:6379
          - redis-5:6379
          - redis-6:6379
        max-redirects: 3
```

---

### 2. **Monitoring and Alerting**

**Key metrics to monitor:**
- Redis connection pool usage
- Redis memory usage
- Rate limit hit rate (429 responses)
- Redis response time
- Gateway request latency

**Example Prometheus metrics:**
```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  metrics:
    export:
      prometheus:
        enabled: true
```

**Grafana Dashboard Panels:**
1. Rate Limit Hit Rate
2. Requests per Second
3. Redis Latency
4. Top Rate-Limited IPs
5. Token Bucket Levels

---

### 3. **Security Considerations**

**A. Secure Redis connection**
```yaml
spring:
  data:
    redis:
      host: redis.internal.company.com
      port: 6379
      password: ${REDIS_PASSWORD}
      ssl:
        enabled: true
```

**B. Rate limit authentication endpoints aggressively**
```yaml
- id: login-route
  uri: http://auth-service:4005
  predicates:
    - Path=/auth/login
  filters:
    - name: RequestRateLimiter
      args:
        redis-rate-limiter.replenishRate: 1
        redis-rate-limiter.burstCapacity: 3
```

**C. Implement IP whitelist/blacklist**
```java
@Bean
public KeyResolver secureKeyResolver() {
    return exchange -> {
        String ip = exchange.getRequest()
                .getRemoteAddress()
                .getAddress()
                .getHostAddress();
        
        if (isBlacklisted(ip)) {
            return Mono.just("blacklisted:" + ip);
        }
        
        if (isWhitelisted(ip)) {
            return Mono.just("whitelisted:" + ip);
        }
        
        return Mono.just(ip);
    };
}
```

---

### 4. **Testing Strategy**

**Unit Tests:**
```java
@Test
void shouldRateLimitRequests() {
    // Send 5 requests (burst capacity)
    for (int i = 0; i < 5; i++) {
        webTestClient.get()
                .uri("/api/patients")
                .exchange()
                .expectStatus().isOk();
    }
    
    // 6th request should be rate limited
    webTestClient.get()
            .uri("/api/patients")
            .exchange()
            .expectStatus().isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
}
```

**Load Tests:**
```bash
# Apache Bench
ab -n 1000 -c 50 http://localhost:4004/api/patients

# k6 load testing
k6 run --vus 100 --duration 30s loadtest.js
```

**Chaos Testing:**
- Kill Redis during high load
- Verify graceful degradation
- Test failover scenarios

---

## 🎯 Key Takeaways

### Core Concepts

1. **Token Bucket Algorithm**
   - Tokens refill at constant rate (replenishRate)
   - Bucket has maximum capacity (burstCapacity)
   - Each request consumes 1 token
   - No tokens = request rejected (429)

2. **Redis as Shared State**
   - Distributed rate limiting across gateway instances
   - Atomic operations ensure accuracy
   - TTL for automatic cleanup
   - Fast in-memory performance

3. **KeyResolver Strategy**
   - Defines how clients are identified
   - IP-based: Simple, works for public APIs
   - User-based: Accurate, requires authentication
   - API key-based: Common for B2B APIs
   - Combined: Most flexible

4. **Configuration Parameters**
   - `replenishRate`: Sustained throughput (req/sec)
   - `burstCapacity`: Maximum instant requests
   - `key-resolver`: Client identification strategy
   - Balance between protection and usability

### Best Practices

✅ **DO:**
- Use Redis for distributed deployments
- Monitor rate limit metrics
- Set appropriate TTLs
- Test under load
- Implement tiered limits
- Return helpful headers
- Log rate limit events
- Use connection pooling
- Set up Redis HA
- Document rate limits for API consumers

❌ **DON'T:**
- Use in-memory rate limiting in production
- Set limits too low (breaks legitimate use)
- Set limits too high (defeats purpose)
- Forget to secure Redis
- Ignore monitoring
- Rate limit health checks
- Use same limit for all endpoints
- Forget about clock skew
- Hardcode limits (make them configurable)
- Rate limit internal services

### Common Patterns

**Pattern 1: Public API**
```
- IP-based rate limiting
- Moderate limits (10-100 req/sec)
- Generous burst capacity
- 429 with retry headers
```

**Pattern 2: Authenticated API**
```
- User ID-based rate limiting
- Tiered limits by subscription
- Track daily/monthly quotas
- Upgrade prompts on limit
```

**Pattern 3: Internal API**
```
- Relaxed or no rate limiting
- Monitor for anomalies
- Circuit breaker for protection
- Focus on backend health
```

---

## 📚 Additional Resources

- **Spring Cloud Gateway Docs**: https://docs.spring.io/spring-cloud-gateway/docs/current/reference/html/#the-redis-ratelimiter
- **Token Bucket Algorithm**: https://en.wikipedia.org/wiki/Token_bucket
- **Redis Rate Limiting**: https://redis.io/docs/manual/patterns/rate-limiter/
- **Stripe Rate Limiting Best Practices**: https://stripe.com/docs/rate-limits

---

*Last Updated: November 2025*