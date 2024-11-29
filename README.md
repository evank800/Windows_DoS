This is a **PoC(Proof of Concpet) for the Windows vunerability CVE-2024-38063**: LAYER 2  vulnerability includes the Windows' inability to process incoming IPv6 Packets properly and graciously, when being sent custom packets (here via Scpay) with the extraheaderextension with an improper padding, causing an integer underflow.



You can find their original code under https://www.exploit-db.com/exploits/52075
**The codes for the actual exploitation is written by Photubias from Exploitdb.**



This project is a tweaking of/expansion to the orignal codes for better performance, as well as additional functionalities such as searching through the local link(Layer 2) to find vulnerable targets, better address parsing schemes, letting the user choose the network interface, as well as automating the exploitation.



CATUION: DO NOT RUN THIS CODE IN AN UNSUPERVISED ENVIRONMENT. 

<video src= 'https://github.com/evank800/Windows_DoS/blob/main/video-output-8064C322-4A9A-445F-8ABC-381A33C41E61.mov'></video>
