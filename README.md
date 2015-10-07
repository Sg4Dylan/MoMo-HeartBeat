#MoMo-HeartBeat


###Overview

这是一个基于 Python 的 NetKeeper 心跳实现脚本，由 [这里的代码](https://github.com/nowind/sx_pi) 修改而来。

相比原repo，增加了读取外置配置文件的功能，方便修改使用。

因为测试环境问题，仅在本地完成了运行逻辑测试，并未在受心跳影响的环境测试过。


##Releases

For Linux-x86_64 [传送门](https://github.com/Sg4Dylan/MoMo-HeartBeat/tree/master/Release/Linux-x86_64)

For Win-x86 [传送门](https://github.com/Sg4Dylan/MoMo-HeartBeat/tree/master/Release/Win_x86)

##Usage

修改 setting.ini 中 userinfo 部分的配置，其中 MAC 地址应填写拨号设备相应 端口/网卡 的 MAC 。

默认为 50 秒一次心跳发送，可自行根据自身情况修改 setting.ini 中 serverinfo 部分的 time 值即可。

修改保存运行即可。


##Troubleshooting

Issues page > [https://github.com/Sg4Dylan/MoMo-HeartBeat/issues](https://github.com/Sg4Dylan/MoMo-HeartBeat/issues)


##License

Under GPL v2 License

