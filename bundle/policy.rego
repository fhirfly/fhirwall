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
validate_consent(input.fhiruser)
}

# Allow Patients, Practitioner, RelatedPerson to get their own FHIR Resource.
allow {
input.method == "GET"
input.resource = input.fhiruser
validateScope
valid_token
validate_consent(input.fhiruser)
}

# Allow Patients to Search their own Patient records.
allow {
input.method == "GET"
input.patient = input.fhiruser
validateScope
valid_token
validate_consent(input.fhiruser)
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

validate_consent(id) {
patient_record(id).status == "active"
patient_record(id).decision == "permit"
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

patient_record(id) := http.send({
    "url": concat("", ["http://localhost:3000/Consent/", id]),
    "method": "GET",
}).body


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

permit_patient_record := {
  "resourceType" : "Consent",
  "id" : "consent-example-basic",
  "text" : {
    "status" : "generated",
    "div" : "<div xmlns=\"http://www.w3.org/1999/xhtml\">\n      <p>\n\t      Authorize Normal access for Treatment\n\t\t\t</p>\n      <p>\n      Patient &quot;Peter James Chalmers (&quot;Jim&quot;)&quot; wishes to have all of the PHI collected at the Burgers University Medical Center available for normal treatment use.\n\t\t\t</p>\n    </div>"
  },
  "status" : "active",
  "category" : [{
    "coding" : [{
      "system" : "http://loinc.org",
      "code" : "59284-0"
    }]
  }],
  "subject" : {
    "reference" : "Patient/example",
    "display" : "Peter James Chalmers"
  },
  "date" : "2018-12-28",
  "controller" : [{
    "reference" : "Organization/f001"
  }],
  "sourceAttachment" : [{
    "title" : "The terms of the consent in lawyer speak."
  }],
  "regulatoryBasis" : [{
    "coding" : [{
      "system" : "http://terminology.hl7.org/CodeSystem/v3-ActCode",
      "code" : "INFA"
    }]
  }],
  "decision" : "permit",
  "provision" : [{
    "period" : {
      "start" : "1964-01-01",
      "end" : "2019-01-01"
    }
  }]
}

test_get_patient_record {
validate_consent("1234567") == true with patient_record as permit_patient_record
}

deny_patient_record := {
  "resourceType" : "Consent",
  "id" : "consent-example-basic",
  "text" : {
    "status" : "generated",
    "div" : "<div xmlns=\"http://www.w3.org/1999/xhtml\">\n      <p>\n\t      Authorize Normal access for Treatment\n\t\t\t</p>\n      <p>\n      Patient &quot;Peter James Chalmers (&quot;Jim&quot;)&quot; wishes to have all of the PHI collected at the Burgers University Medical Center available for normal treatment use.\n\t\t\t</p>\n    </div>"
  },
  "status" : "deactive",
  "category" : [{
    "coding" : [{
      "system" : "http://loinc.org",
      "code" : "59284-0"
    }]
  }],
  "subject" : {
    "reference" : "Patient/example",
    "display" : "Peter James Chalmers"
  },
  "date" : "2018-12-28",
  "controller" : [{
    "reference" : "Organization/f001"
  }],
  "sourceAttachment" : [{
    "title" : "The terms of the consent in lawyer speak."
  }],
  "regulatoryBasis" : [{
    "coding" : [{
      "system" : "http://terminology.hl7.org/CodeSystem/v3-ActCode",
      "code" : "INFA"
    }]
  }],
  "decision" : "permit",
  "provision" : [{
    "period" : {
      "start" : "1964-01-01",
      "end" : "2019-01-01"
    }
  }]
}

test_deny_patient_record {
allow == false with patient_record as deny_patient_record
}