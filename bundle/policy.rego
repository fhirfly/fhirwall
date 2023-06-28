package fhirapi.authz
import future.keywords.every

key := 
{"kty":"RSA","e":"AQAB","n":"xb-v_wfU50NcvmIfdHmAoPPq7TQ0YLgWuFaWKe2laC6v2zo9_lJQfhjVBF3pco2jH--g9AU1SwUfDCS-IwKQm050KNMQLDNkhNwqR2J451XsPk8hvG8cnfw05PO_9V5l-U6ulFNae_MCWRpt4_Dg2Ria_c7JmVHFYktrJDAerTlD6PN2xvwDVZDsd-bSFRX3iGO-sBqTf2q4oMeAGtuvbXAGPILPMUf0oiVUSKB7Zwh0mz7WdbZtX4uXJ6sr32sk9oJFMYZPXeBDycPVSgzthb8F427ZI3c_qyaRj0toZWPX-quRFqSIiLAt2qgWjjFUecnYUhtq5aQKRrOzlWVWUw"}

default allow := false

# Allow all users to get FHIR server metadata.
allow {
input.method == "GET"
input.path == ["metadata"]
validateScope
valid_token
}

# Allow Patients, Practitioner, RelatedPerson to get their own FHIR Resource.
allow {
input.method == "GET"
input.resource = input.fhiruser
validateScope
valid_token
}

# Allow Patients to Search their own Patient records.
allow {
input.method == "GET"
input.patient = input.fhiruser
validateScope
valid_token
}

validateScope {
isValidScope
isValidMethod
}

isValidScope {
scopes = split(input.scope, " ")
every scope in scopes {
startswith(scope, input.role)
}
}

isValidMethod {
scopes = split(input.scope, " ")
every scope in scopes {
finerScope := split(scope, ".")
allowVerb(finerScope[1])
}
}

allowVerb(scope) {
input.method == "GET"
scope == "read"
}

allowVerb(scope) {
input.method == "POST"
scope == "write"
}

allowVerb(scope) {
input.method == "PUT"
scope == "write"
}

allowVerb(scope) {
input.method == "DELETE"
scope == "write"
}


# Token validation
jwt := input.header.token

jwks := json.marshal(key)

# Define the constraints to use with `decode_verify`
constraints := {
  "cert": jwks, 
  "alg": "RS384",
  "aud": "http://localhost/token",
  "iss": "http://localhost",
  "time" : time.now_ns()
}

valid_token := payload {
[valid, _, payload] := io.jwt.decode_verify(jwt, constraints)
valid
}


# Tests
input_allow := {
"method": "GET",
"resource" : "Observation",
"fhiruser": "Patient/1234",
"patient": "Patient/1234",
"scope": "patient/Patient.read patient/Observation.read",
"role": "patient"
}

test_allow_get {
  allow == true with input as input_allow
}

input_deny_put := {
"method": "PUT",
"resource" : "Observation",
"fhiruser": "Patient/1234",
"patient": "Patient/1234",
"scope": "patient/Patient.read patient/Observation.read",
"role": "patient"
}

test_deny_put {
  allow == false with input as input_deny_put
}

input_deny_role := {
"method": "GET",
"resource" : "Observation",
"fhiruser": "Patient/1234",
"patient": "Patient/1234",
"scope": "patient/Patient.read patient/Observation.read",
"role": "system"
}

test_deny_role {
  allow == false with input as input_deny_role
}