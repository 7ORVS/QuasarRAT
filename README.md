# QuasarRAT Analysis


## General Inoformation:

```
MD5 hash: 
769a35589cdbb4c0893c0ec138d21e70

SHA256 hash: 2be793fba87cd5dbc7d1c89f31e2fa18ca34bbaf27a624e09a10f9b962f55373
```

<br>

## Basic Static Analysis

The output from `DIE` told us that this sample is written in `.NET` with high entropy and packing indication:

![](/pics/DIE_1.PNG)

![](/pics/DIE-entropy.PNG)

Here are some suspicious strings from `FLOSS` output:

```
CreateMutex
GetTheResource
AdminCheck
Mutex
_appMutex
Sleep
GetCurrentProcess
set_UseShellExecute
System.IO.Compression
GZipStream
CompressionMode
get_Registry
RegistryKey
OpenSubKey
SetValue
ppbkm.Resources
RunAsDate
RunAsDate.exe
My.WebServices
4System.Web.Services.Protocols.SoapHttpClientProtocol
RunAsDate.exe
System.exe
svchost.exe
svchost.exe|True|True|False|%AppData%|True|False|False
System.exe|True|True|False|%AppData%|True|False|False
RunAsDate.exe|True|False|False|%Temp%|False|False|False

SOFTWARE\Microsoft\Windows\CurrentVersion\Run (Persistence)


```

Ok, so, we see that the malware will use a mutex for something maybe to ensure that only one version is running at a time, we can also see some processes like `svchost.exe` and `RunAsDate.exe` which is repeated a lot on the strings, the most suspicious things those are related to Registry and the `Run` registry which used for achieve the persistence, also we can some stuff for resources, so, let's take a look on `Resource Hacker` to see if this sample hold something interesting inside its resources or not.


Inside the resources section, we will find that this sample has 4 resources, 2 of them `Manifest` and `Version Info`.

In the Manifest file, we will find the Trusted execution level section and in this section, this sample will make itself trusted software, and in Version info, we will see that the sample will declare or something like this the `RunAsDate`.

![](/pics/Mainfest.PNG)

![](/pics/VersionInfo.PNG)

If we take a look at imports we will see that there is a single import from `mscoree.dll`

![](/pics/Imports.PNG)

<br>

## Basic Dynamic Analysis

During the dynamic analysis and running the program, I found some understandable things happened.
The first thing that the program that running is not our sample but `RunAsDate` and the sample will create in 

**AppData\Local\Temp**


![](/pics/process.PNG)

and the second thing is that the sample put `svchost.exe` and `system.exe` into the RUN registry in `HKCU`

![](/pics/svchost.RUN.PNG)

The last thing that the CMD process opened and poped PING process also this process tried to execute a command which will run a .bat file in **AppData\Local\Temp** folder and this file was created and deleted frequently with changed name

![](/pics/processAgain.PNG)

![](/pics/bat.PNG)

![](/pics/bat-delete.PNG)

if we get one of these .bat files and see the content of them we will see that these files ping on localhost and then delete itself.

![](/pics/bat-content.PNG)

When I searched about local host pinging, I found that the malware might be ping on the local host to know what is the IP of the machines or to test your network connection without having to ping an external device.


For the network level, the Wireshark didn't capture anything useful unless a huge number of ARP requests.

![](/pics/ARP-req.PNG)

<br>

## Advanced analysis

If we open this sample on `dnSpy` we find that the Resource section contains 3 files `[RunAsDate.exe, svchost.exe, System.exe]`

![](/pics/Resources-section.PNG)

If we see also that the file itself is named `RunAsDate.exe`, not the name that I named it `QuasarRAT.exe`.

If we open the main method we will see that the sample will sleep for 2 seconds, and then it will create a mutux to ensure that only one version of it is running at a time.

![](/pics/Sleep-and-mutex.PNG)

![](/pics/CreateMutex.PNG)

![](/pics/Mutex-Name.png)


Then the malware will check if it's running under the Administrator or not and if not it will make a process to run under it and continue to the rest of its activities.

![](/pics/Admin-check.PNG)

So, I run the dnSpy as an Administrator and then continue the analysis, the malware now will jump to `workF` function.

So, in the `workF` function will see that the sample will get the 3 files located in the Resources section and put them in the list and then iterate on them to drop them to the file system of the victim machine also it will put the `[svchost.exe, System.exe]` into the Registry key and run the `RunAsDate.exe` process and then exit itself.

![](/pics/Files-Res-sec.png) <br>

![](/pics/put-the-file-into-location.png) <br>

![](/pics/Write-file-to-REG.PNG) <br>

![](/pics/REG-name.PNG) <br>

![](/pics/Open-RuAsDate.PNG) <br>

---

So, now I'll perform an analysis of `RunAsDate.exe` to figure out what this malware does in the system


## RunAsDate.exe Analysis

If we open this executable on `DIE` we will find that this executable is packed using `UPX`

![](/pics/RunAsDate/UPX-packing.PNG)

So, I use this command to unpack it

```
upx -o the_real_RunAsDate.exe -d RunAsDate.exe
```
And get the unpacked file to perform the rest of the analysis.

