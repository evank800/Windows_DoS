This is a **PoC(Proof of Concpet) for the Windows vunerability CVE-2024-38063**. 

**The codes for the actual exploitation is written by Photubias from Exploitdb.**

You can find their original code under https://www.exploit-db.com/exploits/52075


The vulnerability includes the Windows' inability to process incoming IPv6 Packets properly and graciously, when being sent custom packages (here via Scpay) with the headerextension with an improper padding, causing an integer underflow.


This project is a tweaking of/expansion to the orignal codes for better performance, as well as additional functionalities such as searching through the local link(Layer 2) to find vulnerable targets and automating the exploitation. 


CATUION: DO NOT RUN THIS CODE IN AN UNSUPERVISED ENVIRONMENT. 
