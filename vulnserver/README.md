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
This will be the result if you type **HELP**

![HELP_cmd](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/HELP_command.png)

Notes:
>We can use these command to test if the target is vulnerable to bufferoverflow. 
>We will try use STATS but **spoiler alert, TRUN is the correct payload for this exercise.

3. We will create files with payload and try if the target machine is vulnerable to bufferoverflow. Create a filed called '[stats.spk](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/stats.spk)' and ‘[trun.spk](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/trun.spk)’

>stats.spk

````spk
s_readline();
s_string("STATS ");
s_string_variable("0");
````
>trun.spk

```
s_readline();
s_string("TRUN ");
s_string_variable("0");
```
4. Open **IMD** as administrator, click File > Attach > select vulnserver > click Attach > click the run icon ![IMD_run_icon](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/IMD_run_icon.png)

![file_attach_img](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/file_attach.png)

![vulnserver_attach_img](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/vulnserver_attach.png)

It will look something like this:

![imd_vulnserver_attached_img](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/imd_vulnserver_attached.png)

Note:

>- In the lower right you can see the status **Paused** ![paused_img](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/paused.png) \
>- Click the run button on the menu ![IMD_run_icon](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/IMD_run_icon.png) to change the status to **Running** ![running_status](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/running.png) 

5. On Kali, run **generic_send_tcp** <target_ip> <port> <payload_file.spk> 0 0.

```
$ generic_send_tcp 192.168.17.134 9999 stats.spk 0 0
```
![fuzzing_output_img](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/fuzzing_output.png) 

>**IMPORTANT NOTE!** Always close and re-run the IMD and vulnserver.exe as administrator before doing new attack test.

6. Check the **IMD**, **STATS** command will not make the target crash so we will try the **TRUN** command.

```
$ generic_send_tcp 192.168.17.134 9999 trun.spk 0 0
```

>- Check the **IMD** again and it should look like this. We can see bunch of **A**s and hex **41414141** \
>- **41** means hex of letter **A**. Four bytes of **41** is equal to hex **41414141** \
>- Our payload using **TRUN** command is successful and made the vulnserver crashed!!! Now we confirmed that the server is vulnerable to bufferoverflow!

![spiking_srcshot](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/spiking_srcshot.png) 

>**Q: How and why the system crashed?** \
>A: By sending bunch of As, to the stack buffer. The stack buffer (EAX register) over flows and we successfully allocated As to the Base Pointer (EBP) and Instruction Pointer (EIP). We can see that EBP and EIP values are all 41414141


>**Q: What is EIP and why it is very important to understand?** \
>A: The Instruction Pointer (IP) is where the actual command executes!! So, if we can overwrite this, we can send malicious code and gain reverse shell.

## II. Fuzzing

1. We will automate the sending of bunch of As using python script. Make a python2 script ‘fuzz.py’ and copy paste this script.

>fuzz.py

````python
#!/usr/bin/python
import sys, socket
from time import sleep

buffer = 'A' * 100 

while True:
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(('192.168.17.134', 9999))

		s.send(('TRUN /.:/' + buffer))
		s.close()
		sleep(1) 
		buffer = buffer + 'A' * 100
		
	except:
		print "Fuzzing crashed at %s bytes" % str(len(buffer)) 
		sys.exit()

````

> Dont forget to change its permission to executable. 

```
$ chmod +x fuzz.py
```

>**Q: What does this code do?**
>A: The script sends 100 As to the vulnserver then it adds another 100 As, so the buffers grows every iteration until it crash.

2. Close and re-run the **IMD** and **vulnserver.exe**. Re-attach vulnserver to IMD then hit the Run button. Makse sure the status is '**Runing**'.

3. Run the python2 script:

```
$ ./fuzz.py
```

4. Observe the **IMD** and wait for it to crash then immediately terminate the fuzz.py script by pressing **CTRL + C**. \
   We can see in the **IMD* that the vulserver crash by checking its status to **Paused** and also we see again the bunch of As in the **Registers** section.

![fuzzing_crashed](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/fuzzing_crashed.png)

5. We see that the vulnserver crashed at around 2200 bytes. So the Offset must be less than 2200 bytes. \
   If you CTRL + C and your result is not 2200 bytes, that's okay because the Offset must be less than what you get in the result.

## III. Finding the Offset
















































