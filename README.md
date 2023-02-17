# BeholderWifi
                        Beholder V. 0.8.9

          Nelson Murilo <nmurilo@gmail.com> (main author)

                 No illegal activities are encouraged!
         I'm not responsible for anything you may do with it.

                This tool includes a portion of software developed 
                by Jean Tourrilhes for Wireless-Tools package. 

-----------------------
1. What's beholder? 


Beholder is a tool to detect some anomalies in wifi enviroment, such as
suspicious changes in essid, also in mac encryption protocol or channel for legitime networks. Generate alerts for new "suspect"
networks and it detects passive malicious hotspot tools, like karma, airbase-ng and hotpotter. 
It also can detects similar essid names and alert for APs suddenly disappear based on regular expressions.
By default, beholder can detect Judicious KARMA, and some types of jamming 

--------------------
2. Supported Systems


Beholder currently works only on Linux machines. 

-------------

3. Instalation 

# make sense

PS: Please ignore "warning: the use of `mktemp' is dangerous, better use mkstemp` or `mkdtemp'" message, we won't create a temporary files, that is only an easy way to create random essids. 

---------
4. Usage

beholder [options] <wifi_device> 

Options:

        -s      send reports to syslog instead to console. 
        -a      add new networks on the initial network table (usual option) 
        -r      regular expression to check essid name variations (case insensitive by default)
        -m      regular expression to check disappeared essid name 
        -c      clever mode. Detect similar essid based on same length and similar name. Regular expression is not used here. 
        -d      debug 
        -dd     verbose  

Regular expression option works without limitations, please spend a time to learn about regex, to explore all potential of this. 

Example: 
beholder -r ".*[1i]nf[0o]s[3e]c.*" 
It matchs with "0infosec", "inf0sec","1nfosec-1", etc. 

beholder -r ".*[1i]nf[0o]s[3e]c.*" -m ".*companynet.*"
It matchs with "0infosec", "inf0sec","1nfosec-1" and start with "companynet"

-----------------------
5. Reports and questions
Please send comments, questions and bug reports to nelsonatpangeia.com.br.

-----------------------
6. ACKNOWLEDGMENTS
Many thanks to Andre, Luiz Eduardo, Ronaldo Vasconcellos and Willian Caprino for really nice ideas and bug reports. 


