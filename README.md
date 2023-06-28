# fhir-opa
Open Policy Agent for FHIR APIs

## How to run
- Create an OPA bundle that will pack the policy into a bundle using below command,

`./opa build -b rules/`

- Then place the bundle inside a folder along with the Dockerfile.
- To build and run the docker container,
      From the above same folder execute
  
        `docker build -t my-opa:0.1 .`
  
        `docker run -p 8181:8181 my-opa:0.1`

With this OPA will be running with the policy loaded.
Now it can be consumed RESTfully as below,

POST : http://localhost:8181/v1/data/fhirapi/authz/allow

Body:

``{"input": {"header": {
"token": "<token_value>"
},
"method": "GET",
"resource" : "Observation",
"fhiruser": "Patient/1234",
"patient": "Patient/1234",
"scope": "patient/Patient.read patient/Observation.read",
"role": "patient"
}
}``



