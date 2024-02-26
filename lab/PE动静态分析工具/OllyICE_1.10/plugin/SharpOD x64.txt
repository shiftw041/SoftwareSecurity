

		OllyDBG/x64dbg plugin  - SharpOD v0.6b
			by StriveXjun
====================================================================


https://bbs.pediy.com/thread-218988.htm
2017-7-5 10:32 


SharpOD v0.6b 更新说明
1.增加 x64dbg Remove EP Break
2.增加 x64dbg Atti_Atti Attach
3.增加 ollydbg 随机三级菜单标题
4.完善下 VMP3.1(above)功能。
5.修复 x64dbg 以管理员重新启动，窗口消息未还原，崩溃的BUG
6.修复 x64dbg 64位程序与火绒安全软件抢Hook点导致程序崩溃的BUG
7.修复 取explorer.exe 进程PID不到，父进程PID变成4的情况。
9.优化代码

插件说明
简介
SharpOD x64 插件是一款只支持64位系统的(Win7,8,10) 反反调试插件，并且支持x32dbg和x64dbg

前言

个人见解先来谈谈各插件功能

StrongOD：非常优秀的一款插件，几乎完美，因在64位系统加载不上驱动，只能在32位系统上发挥其威力，海风大牛也没时间更新，这真是个悲剧。
PhantOm: 插件精简高效，但使用了SSDT Index硬编码来拦截 wow64cpu!Wow64Transition(32位转64位模式的地方 jmp 0033:xxxxxxxxx)导致兼容性也不是那么的好。
而且处理的东西也非常少，Wow64进程的peb64也没有处理，故导致很多的反调试过不去。

scyllaHide: x64dbg作者开发的一款非常优秀隐藏插件，同上也是Hook wow64cpu!Wow64Transition(32位转64位模式的地方 jmp 0033:xxxxxxxxx),而且处理了非常多的地方。
我看完了scyllaHide的源代码，界面复杂，发现作者有点赖 - -！，很多地方处理不够精细，并且硬件断点保护作者嫌64位麻烦也是没写，并且Hook位置不够深,别人随便调用个64位API就检测到了。

titanHide: 在64位系统上SSDT Hook，首先用户就要去过一遍PG了，而且处理的地方也不多。
以上插件各有其优缺点，就是找不到一个完美点的，且现在越来越多的64位系统，在64位系统上没能找到一款顺手插件导致被很多软件anti到,故编写了SharpOD x64插件。。
SharpOD x64主要实现是向wow64进程 ，注入纯64位code，并且hook ntdll64 api来实现的，这样做要比Hook wow64cpu!Wow64Transition要底层的多。

具体功能请看下面介绍

安装

Ollydbg: 拷贝SharpOD x64.dll 到您的OD插件目录，并且拷贝StrongOD插件到OD插件目录(StrongOD在64位上主要用于修复OD的BUG和非常好用的快捷键)
然后重启调试器在插件菜单中配置

x64dbg: 拷贝对应版本的插件到你的x64dbg插件目录,如64位,拷贝SharpOD x64.dp64文件,然后重启调试器在插件菜单中配置


功能说明
->Hide PEB (重载程序生效)
隐藏PEB，处理掉以下特征
peb.BeingDebugged & wow64.peb64.BeingDebugged
peb.NtGlobalFlag & wow64.peb64.NtGlobalFlag
peb.processHeap.HeapFlags & wow64.peb64.processHeap.HeapFlags
peb.processHeap.ForceFlags & wow64.peb64.processHeap.ForceFlags

-> Change Caption (重启调试器生效)
无力吐槽的功能，恕我直言，一切带特征的反调试都是不安全的。 
而这个功能就是在改变调试器 窗口标题、菜单名称 来防止小学生的枚举窗口以及菜单检测。

-> Hide Process (重载程序生效)
隐藏进程功能，只针对正在调试的进程，在NtQuerySystemInformation断链 

-> Fake ParentProcess (重载程序生效)
修改父进程标识符，调试的进程 父进程会变成explorer.exe的，如果取不到explorer.exe 的pid，则会把父进程变成4.

-> Drag Attach (重启调试器生效)
感觉这个是最给力的更新了，只要拖动调试器左上角的图标 到目标窗口上，即可附加进程。 

->Hook *ZwFunctions (重载程序生效)
Hook Zw系列函数
这个处理的东西太多了，以下Nt函数 
NtQuerySystemInformation
SystemKernelDebuggerInformation
SystemProcessInformation
SystemHandleInformation
NtClose
invalid Handle
NtQueryInformationProcess
ProcessBasicInformation
ProcessDebugPort
ProcessDebugObjectHandle
ProcessDebugFlags
NtSetInformationThread
ThreadHideFromDebugger
NtDuplicateObject
NtQueryObject
ObjectTypesInformation -> DebugObject
NtYieldExecution
return STATUS_NO_YIELD_PERFORMED


-> Remove DebugProvileges (重载程序生效)
移除调试进程的调试权限
因为默认情况下进程没有SeDebugPrivilege权限，调试时会从调试器继承这个权限,以不免有人利用这一点。默认不建议开启 

-> VMP 3.1(above) (重载程序生效)
过VMP3.1以上版本的反调试
VMProtect 3.1版本开始有重大的更新，从这个版本开始，直接模拟Wow64 调用syscall进入内核，32位的系统也是直接调用特权指令systnter进入内核，查询检测ProcessDebugObjectHandle，所以在应用层几乎没有办法拦截他。
我这里使用了一个小trick绕过了他的检测。

-> Protect Drx (重载程序生效)
保护硬件断点 
ZwSetContextThread
ZwGetContextThread
KiUserExceptionDispatcher -> if Wow64PrepareForException
RtlDispatchException
RtlRestoreContext

->Driver Hook SSDT (重启调试器生效)
使用此功能，所有用户电脑都得去过PatchGuard，非常麻烦，等必要的时候在加上去。

->Driver Hook ShadowSSDT (重启调试器生效)
 
->Driver Dbg ValidAccessMask (重启调试器生效)
此功能专门针对那些 模仿TP反调试 来清除你的DebugObject->ValidAccessMask ,谁给你的这么大的权力来全局清除我机器的调试对象?
现象是你的调试器无法拖入任何程序。

->Driver bypass ObjectHook (重启调试器生效)
绕过 object hook，这个保护在 64位系统上用的最多，他可以过滤掉你打开进程的权限。
比如让你无法对目标进程内存读写等。开启这个功能即可绕过这个保护。但好像WIN10系统下会触发PG
[SharpOD x64 v0.6更新]
完整的重写架构以及代码,不在和ScyllaHide、PhantOm冲突，比它们更加底层。
支持所有64位系统，不在使用 SSDT Index 硬编码
支持x32dbg、x64dbg

[SharpOD x64 历史版本重要更新]
v0.5c
修复一个调用驱动功能BUG
v0.5b
重写Hook框架，修复一个死循环BUG
增加了随机 OD窗口菜单、子菜单、全部子窗口标题
v0.5
增加保护硬件断点
增加过VMP3.1以上的反调试
增加驱动
v 0.4
加入开关界面显示框，处理窗口标题。
v0.3
重写Hook框架，支持大多数壳的反调试
v0.2内测版
支持WIN10系统
v0.1内测版
一个简单的demo版本