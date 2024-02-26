2020.6.29更新
1）新增插件FullDisasm.dll（解决部分指令识别不正确，如MMX、SSE支持）和+BP-OLLY.dll（会新增一个快捷菜单，有常见的断点命令）；
2）整合bxc提供的OD可用lib库文件，存放路径在/LIB，打开OD->调试->选择导入库可查看；
3）将ODbgScript常见胶壳脚本整合进来，和路径在/Scripts。


2020.5.25更新
1）更新插件SharpOD x64（作者StriveXjun），该插件是一款只支持64位系统的(Win7,8,10) 反反调试插件。
StrongOD非常优秀的一款隐藏插件，在64位系统加载不上驱动，只能在32位系统上发挥其威力，而SharpOD，可以使得OD在x64平台上隐藏（注意：调试的程序还是32位）。


2016.1.18更新
1）更新插件OllyWow64.dll，使OllyDBG 1.1可以在64位windows平台下调试32位程序。
2）放进Microsoft  Win32 API手册的CHM
3）更新插件PatchUnicodeProc，解决OllyDBG 1.1不能对unicode程序设消息断点的bug，并使OllyDBG 1.1支持直接F1快捷键打开CHM帮助文档；

2008.1.1更新
OllyICE v1.10 修改版 [2008.1.1]

由于OllyDBG 1.1（http://www.ollydbg.de）官方很长一段时间没更新，故一些爱好者对OllyDBG修改，新增了一些功能或修正一些bug，OllyICE就是其中的一个修改版，取名OllyICE只是便于区分，其实质还是OllyDBG，版权归OllyDBG官方所有。

文件组成：
OllyICE.EXE 中文汉化版，是在cao_cong汉化第二版基础上修改的。
OLLYDBG.EXE 英文修改版，修改的地方与OllyICE.exe一样。

OllyICE.EXE与OLLYDBG.EXE同时做了如下修改：
1.窗口、类名等常见修改；
2.格式化字符串的漏洞[OutPutDebugString]补丁；
3.参考dyk158的ODbyDYK v1.10 ，自动配置UDD、PLUGIN为绝对路径；
4.参考nbw的"OD复制BUG分析和修正"一文,修正从内存区复制数据时,有时无法将所有的数据都复制到剪贴板的bug。
5.参考ohuangkeo“不被OD分析原因之一和修补方法”，稍改进了OD识别PE格式能力(可能仍报是非PE文件，但己可调试了)。
6.修正OllyScript.dll插件bpwm命令内存读写都中断的问题。
7.jingulong的Loaddll.exe，可以方便让OllDbg中断在dll的入口。
8.感谢DarkBul告知SHIFT+F2条件窗口显示的bug及修复。
9.感谢dreaman修复Findlabel,Findname,Findnextname三个函数处理字符串会溢出的bug。
10.改善sprintf函数显示某些浮点数会崩溃的bug，这里的修复代码直接引用heXer的代码。
11.该修改版，配合HideOD插件，可以很好地隐藏OD。
12.新增实用的快捷键功能
13.修正Themida v1.9.x.x检测OllyICE的Anti，配合HideToolz即可调试Themida v1.9.x.x加壳程序。 
14.LOCKLOSE添加了部分API和结构体信息。


看雪学院: http://www.kanxue.com
