# ACME Notes

---

## Basics

### General Process

##### 1. Account Creation

1. client generates an asymmetric key pair

2. client requests a new account (optionally providing additional info)

3. The creation request is signed with the generated private key

4. Server sends account url & account object

##### 2. Cert Issuance

1. Submit an order for a certificate to be issued

	- The desired identifiers 
	- A few additional fields that capture semantics that are not supported in the CSR format

2. Prove control of any identifiers requested in the certificate

	- If the server is willing to consider issuing such a certificate, it responds with a list of requirements that the client must satisfy
	- The server will choose from an extensible set of challenges that are appropriate for the identifier being claimed
	- The client responds with a set of responses that tell the server which challenges the client has completed.

3. Finalize the order by submitting a CSR

	- PKCS#10 Certificate Signing Request
	- Server ACK

4. Await issuance and download the issued certificate

##### 3. Cert Revocation

1. Client sends a signed revocation request

![image-20211008154852539](/Users/yuening/Library/Application Support/typora-user-images/image-20211008154852539.png)

### Resources & Cert

##### Cert Management functions

- Account Creation
- Ordering a Certificate
- Indentifier Authorization
- Cert Issuance
- Cert Revocation

##### Resources

- server must provide "directory" and "newNonce" resources
- each function is listed in a directory along with its corresponding URL, so clients only need to be configured with the directory URL ![image-20211008154548159](file:///Users/yuening/Library/Application%20Support/typora-user-images/image-20211008154548159.png?lastModify=1633701309)

###### A "directory" resource

- the only URL needed to configure clients
- JSON object: field + url
  - newNonce, newAccount, newOrder, newAuthz, revokeCert, keyChange
- "meta" field:

###### A "newNonce" resource

###### A "newAccount" resource

###### A "newOrder" resource

###### A "revokeCert" resource

###### A "keyChange" resource

###### Account resources

###### Order resources

###### Authorization resources

###### Challenge resrouces

###### Certificate resources

---

## Implementation Details

#### Character Encoding

- General: ==UTF-8==

- Identifiers that appear in certificates may have their own encoding considerations. Any such encoding considerations are to be applied **prior to** the aforementioned UTF-8 encoding.

	- DNS names containing non-ASCII characters are expressed as ==A-labels== rather than U-labels
	- Binary fields in JSON objects used by ACME are encoded using ==base64url encoding==
	  - URL safe character set
	  - **Trailing '=' characters MUST be stripped**

#### Cryptography

- An ACME server MUST implement the "ES256" signature algorithm [RFC7518] and SHOULD implement the "EdDSA" signature algorithm using the"Ed25519" variant (indicated by "crv") [RFC8037].


#### Message Transport

- Over **HTTPS**

- Using **JWS (JSON Web Signature)**

  - All ACME requests with a non-empty body MUST encapsulated their payload in a JWS object

    - in the **Flattened JSON Serialization**

    - NOT have multiple signatures

    - Not use Unencoded Payload Option 

    - Not use Unprotected Header

    - **Payload must NOT be detached**

    | Fields | Description               |
	  | ------ | ------------------------- |
	  | ==alg== | *"none"* or *a MAC algorithm* |
    | ==nonce== | - provided by the server<br> -> in the HTTP Replay-Nonce header field<br> -> also in error responses (400 - "urn:ietf:params:acme:error:badNonce")<br>- Must be *an octet string encoded accounting to the base64url*<br>- Should NOT included in HTTP request message |
    |==url==|the client must set the value to *the exact string* provided by the server |
    | ==jwk== / ==kid== | - "jwk": JSON Web Key <br> -> *public key*<br> -> [**newAccount & revokeCert requests**]<br> - "kid": Key ID <br> -> *the account URL* received by POSTing to the newAccount resource)<br> -> [other requests] |
  
  - Provide an integrity mechanism -> against intermediary changing the request URL to another ACME URL
  
- **POST-as-GET Requests**

  - For Authentication (405 - "malformed")
  - POST with a JWS body, where the payload of the JWS is**a zero-length octet string (empty string)** 
  - *GET Requests for the dirctory and newNonce resources*

- **Rate Limits**

  - Ensure fair usage and prevent abuse
  - Exceed the limit ("urn:ietf:params:acme:error:rateLimited")

- **Errors**

  - At *the HTTP layer* OR within *challenge objects*
  - provided additional information using a problem document
    - Client *SHOULD display the "detail" field of all error*
  - **"type" field**: "urn:ietf:params:acme:error:<_type_>"
  - Subproblems:
    - JSON array of problem documents
    - **"identifier" field**

#### HTTPS Requests

###### ACME Client
| Header Field | Details |
|--------------- | -------- |
| ==User-Agent==                                  | name & version of ACME software |
| Accept-Language | to enable localization of error me |
| ==Content-Type== | "application/jose+json" |











