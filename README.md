# fhirwall
fhirwall: OPA-based FHIR API Authorization
Table of Contents
Introduction
Features
Requirements
Installation
Usage
Contributing
License
## Introduction
Welcome to fhirwall! fhirwall is a software package that enforces authorization rules on Fast Healthcare Interoperability Resources (FHIR) APIs. It leverages the power of Open Policy Agent (OPA) to help you protect sensitive healthcare data and ensure that only the appropriate entities have access to it.

## Features
With fhirwall, you can:

Implement fine-grained authorization policies for FHIR APIs.
Evaluate authorization requests against policies written in Rego, OPA's high-level declarative language.
Utilize dynamic context in policy decisions, considering factors such as roles, relationships, and resource attributes.
Efficiently manage policy changes with OPA's capabilities for hot-swapping and versioning.
Ensure secure access to your FHIR resources and protect them from unauthorized access.
Leverage customizable templates for standard policy structures, simplifying policy creation and maintenance.
Monitor and log access attempts and outcomes for compliance and auditing purposes.

## Requirements
Docker
Open Policy Agent (OPA)
FHIR API

## Installation
To install fhirwall, you must first ensure you have Docker installed and running on your system. Afterward, you can pull the fhirwall image from Docker Hub.

```$ docker pull your-org/fhirwall```

Next, run fhirwall with the correct configuration file.

```$ docker run -p 8181:8181 -v /path/to/config:/config your-org/fhirwall```

## Usage
fhirwall is designed to intercept API requests and enforce authorization policies.

Define your policies in Rego and load them into fhirwall.  fhirwall currently provides a powerful, standards based policy file that supports Smart on FHIR, and other advanced features. 
whirwall will evaluate incoming API requests against these policies.

For a detailed guide on policy creation, please refer to our The REGO language and the Open Policy Creation Guide.

## Contributing
We welcome contributions to fhirwall! If you're interested in contributing, please read our Contributing Guidelines for information on how to get started.

## License
fhirwall is licensed under the MIT License. For more information, please refer to the LICENSE file in this repository.

## How to test the API
From your FHIR API, atre performing your smart on FHIR authentication service, Your API can call fhirwall with the follwing REST call: 
```
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
}```



