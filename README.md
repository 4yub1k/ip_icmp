# ip_icmp
Manual crafting ICMP/IP\
Change the Soure and Destionation IPS\
__Blue Print Of Packet :__

![icmp](https://user-images.githubusercontent.com/45902447/147408642-ef7f78b8-ea5c-4d2e-95c5-d502b4488665.jpg)

__Script Outputs:__
```
Checksum Calculations ICMP :

Checksum = 0xFFFF - ( Type | Code + checksum(0x0000) + Identifier + Sequence Number )
Checksum = 0xFFFF - ( 0x800 + 0x0000 + 0x1234 + 0x001 + Carryover(0x0000) ) = 0xe5ca
```
__Checksum ICMP :__

![icmpheader](https://user-images.githubusercontent.com/45902447/147408652-965b0fc3-ffa8-418e-b218-9d8c02a5ea6d.jpg)


__Checksum IP :__

![ipdeaher](https://user-images.githubusercontent.com/45902447/147408657-420aae7d-74f9-42da-bd3b-1ac4bfc621c2.jpg)


__Headers :__

![icmp_output](https://user-images.githubusercontent.com/45902447/147408661-d6b02d02-2ee7-4c3f-9462-9ad726336b0f.jpg)

