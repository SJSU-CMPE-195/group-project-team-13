Network Monitoring Lab Setup

Hardware
- HP 2530-8G managed switch
- Raspberry Pi 5 (IDS sensor)
- Kali Linux attacker machine- I installed Kali OS on one of my computers in order to perform attacks.
- Victim host machine- Just a Windows computer

  How I configured the switch

  I first enabled port mirroring on the switch to copy traffic from active ports to the Raspberry Pi monitoring interface.
  Every switch has a console port. I connected to the console port with a console cable. This allowed me to view the console on my computer.

  The first thing I did was reconfigure the switch. Then I input these commands: 
mirror-port 8
interface 1 monitor
interface 2 monitor



   Port roles:
Port 1 – Victim machine
Port 2 – Attacker machine
Port 8 – Raspberry Pi IDS sensor
   


