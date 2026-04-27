# SKILL: API Security Testing

## Description
REST/GraphQL API security assessment methodology covering auth bypass, IDOR, injection, and business logic flaws.

## Trigger Phrases
api, rest, graphql, jwt, oauth, idor, swagger, openapi, endpoint, bearer, token

## Methodology

### Phase 1: Discovery
1. Find API docs: `/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql`
2. Crawl with Burp/ZAP, extract endpoints
3. Check CORS: `curl -H "Origin: https://evil.com" -I <url>`
4. Enumerate versions: `/api/v1/`, `/api/v2/`, `/api/v3/`
5. GraphQL introspection: `{__schema{types{name,fields{name}}}}`

### Phase 2: Authentication
1. **JWT attacks**: None algorithm, weak secret (hashcat), kid injection
2. **OAuth**: redirect_uri manipulation, scope escalation, token leakage
3. **API keys**: Check for key in URL/headers, test key rotation
4. **Session**: Check for session fixation, cookie security flags

### Phase 3: Authorization (IDOR/BOLA)
1. Replace user IDs in URLs: `/api/users/123` → `/api/users/124`
2. Change UUID/GUID references in request body
3. Test horizontal privesc: access other users' resources
4. Test vertical privesc: access admin endpoints as regular user
5. Mass assignment: add `"role":"admin"` to update requests

### Phase 4: Injection
1. SQL injection in parameters and JSON body
2. NoSQL injection: `{"$gt":""}`, `{"$ne":""}`
3. Server-Side Template Injection via API input
4. Command injection via filename/path parameters
5. GraphQL: nested query DoS, batch query abuse

### Phase 5: Business Logic
1. Race conditions: send concurrent requests
2. Rate limiting bypass: IP rotation, header manipulation
3. Price manipulation in e-commerce APIs
4. Skip workflow steps (e.g., skip payment)
