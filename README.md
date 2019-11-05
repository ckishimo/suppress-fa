### suppress-fa
- Script that emulates the cisco suppress-fa cli command for OSPFv2
- The OSPF Forwarding Address Suppression in Translated Type-5 LSAs feature causes an NSSA ABR to translate Type-7 LSAs to Type-5 LSAs, but use the 0.0.0.0 as the forwarding address instead of that specified in the Type-7 LSA
- This feature causes the router to be noncompliant with RFC 1587
- In short, if routers do not have the knowledge on how to reach the forwarding address, due to some kind of lsa filtering, you can suppress the FA route advertisement and suppress this value, this would results that the FA be equal to 0.0.0.0 which forces the use of the ASBR to reach the destination.
- Link: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_ospf/configuration/15-mt/iro-15-mt-book/iro-for-add-sup.html

