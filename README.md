<h2>This is a PoC(Proof of Concpet) for the Windows vunerability CVE-2024-38063</h2><h4> LAYER 2  vulnerability includes the Windows' inability to process incoming IPv6 Packets properly and graciously, when being sent custom packets (here via Scpay) with the extraheaderextension with an improper padding, causing an integer underflow.</h4>



You can find their original code under https://www.exploit-db.com/exploits/52075
**The codes for the actual exploitation is written by Photubias from Exploitdb.**



This project is a tweaking of/expansion to the orignal codes for better performance, as well as additional functionalities such as searching through the local link(Layer 2) to find vulnerable targets, better address parsing schemes, letting the user choose the network interface, as well as automating the exploitation.



CATUION: DO NOT RUN THIS CODE IN AN UNSUPERVISED ENVIRONMENT. 

<h2>Demo</h2>
<h3>This is a demo of the code on the windows 10 virtual machine running on linux</h3>
<h4>I have chosen the virtual network interface vnet0 as interface that will be sending the custom packets. After exactly 60 seconds, the windows machine crashes, causing BSoD</h4>


https://github.com/user-attachments/assets/4fa544d4-9698-4115-a0af-543ba3d85ced

