# Roadmap

## Minimum viable product
- Add tests (and CI)
- Add config interface to send capture to (one network card for capture, the other to send capture)
- Have apikey expected to be given at a parameter
- Limit the rights necessary for whisperer (root currently)
- Call Poller Config every x minutes to check for change. Kill and restart. 1 hour before EoL of JWT token, reconnect with ApiKey to get a new one. 
- Have whisperer in OpenSource to ensure no spyware... LoL
- JSON-LD contexts
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