# Roadmap

## Minimum viable product
- Add config interface to send capture to (one network card for capture, the other to send capture)
- Have a local DNS cache valid for 1 hour (conf) and send the hostnames to server for every change
- Have token expected to be given at a parameter / could be generated at first start of Docker
- Get configuration from conf server based on token
- JSON-LD contexts
- Add tests (and CI)
- Authentication
- Security
- HealthCheck
- Documentation
  * Readme
  * Architecture
- Docker (one generic image)

## 2nd step
- What about sessionless packets?
- Load complementary code from server (tcp...)
- Load the processing code from the server
- Get CPU/RAM at same time?