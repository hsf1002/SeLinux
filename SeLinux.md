
##### SeLinux
Security-Enhanced Linux，是一种基于域-类型（domain-type）模型的强制访问控制（MAC）安全系统，其原则是任何进程想在SELinux系统中干任何事，都必须先在安全策略的配置文件中赋予权限。凡是没有在安全策略中配置的权限，进程就没有该项操作的权限。在SELinux出现之前，Linux的安全模型是自主访问控制DAC，其核心思想是进程理论上所拥有的权限与运行它的用户权限相同。比如以Root用户启动shell，那么shell就有Root用户的权限，在Linux系统上能干任何事。这种管理显然比较松散。在SELinux中，如果需要访问资源，系统会先进行DAC检查，不通过则访问失败，然后再进行MAC权限检查

##### SeAndroid
Android在SELinux的基础上扩展了SEAndroid，两者原理上差不多，但是SEAndroid面向的对象更丰富，到了Android 5.0之后才完全深度整合了SELinux和SEAndroid。SELinux两个最基本的对象是主体（Subject）和客体（Object）。主体和客体分别对应的是“进程”和“文件”。这里的文件并不单指的是实际存在的文件，而是指Linux里“一切皆文件”里指的文件, 如Socket，系统属性等。在SEAndroid，对主体和客体进行了进一步形式上的封装和扩展，细分为：系统文件，服务，系统属性，Bindert和Socket等

##### DAC与MAC
DAC：Discretionary Access Control
MAC：Mandatory Access Control
通俗地讲，在DAC里，如果一个应用获取了一个用户权限，如Root，那他的所有操作操作都是基于这个用户权限。而MAC就简单霸道好多，无论你是谁，甚至是有Root用户权限，文件权限为777，但每个动作都是需要被允许之后可以被执行
1. MAC机制基于 LSM(Linux Security Module) 标准实现
2. SELinux在MAC上实现，所以也是基于LSM标准，在Linux kernel 2.6后正式直接整合进Linux里面
3. MAC的安全策略文件的作用，学名是TEAC（Type Enforcement Access Control），简称TE，称为强制类型语言
4. Security Context，安全上下文，其作用就是相当于这些文件和进程的“身份证”
5. SELinux Mode，分为Permissve Mode（宽容模式）和Enforcing Mode（强制模式）。区别在于Permissive只会打印SELinux Log，而强制模式会进行真正拦截。如果被拦截，kernel log中的关键字是"avc:denied"

SELinux在初始化的时候会实现一些由LSM提供的抽象函数（abstract）和把一些LSM回调（Hook）注册进LSM，LSM会读取SELinux里database的TE规则，或者在AVC（AccessVector cache）里寻找相应的规则，AVC相当于一个规则的缓存，加快读取的速度。找到相应的规则后又把它传回LSM，在LSM里做出最后的判断

##### SEAndroid app
SELinux(或SEAndroid)将app划分为主要三种类型(根据user不同，也有其他的domain类型)
1. platform_app：有android平台签名，没有system权限
2. system_app：有android平台签名和system权限
3. untrusted_app：第三方app，没有Android平台签名，没有system权限

从上面划分，权限等级，理论上：untrusted_app < platform_app < system_app

##### 配置文件
```
a. external/sepolicy/attributes     -> 所有定义的attributes都在这个文件
b. external/sepolicy/access_vectors -> 对应了每一个class可以被允许执行的命令
c. external/sepolicy/roles -> Android中只定义了一个role，名字就是r，将r和attribute domain关联起来
d. external/sepolicy/users -> 其实是将user与roles进行了关联，设置了user的安全级别，s0为最低级是默认的级别，mls_systemHigh是最高的级别
e. external/sepolicy/security_classes -> 指的是上文命令中的class，内容是指在android运行过程中，程序或者系统可能用到的操作的模块
f. external/sepolicy/te_macros -> 系统定义的宏全在te_macros文件
g. external/sepolicy/***.te    -> 包含了各种运行的规则
```

##### 策略分离
伴随着system image 和 vendor image 的分离, 自然也会伴随着sepolicy 的分离, 从以往集中放在bootimage, 到分离存放到system image 以及 vendor image。原则上与system 相关的sepolicy 就存放system image, 与SoC vendor 相关的sepolicy 就存放在vendor image

在Android8.0中，SELinux策略分离成平台（platform）和非平台（non-platform）两部分，平台策略又分为平台私有（platform private）和平台公有（platform public）
1. public：平台共有策略全部定义在/system/sepolicy/public下，public下的type和attribute可以被non-platform中的策略所使用，即设备制造商的sepolicy作者在non-platform下可以对platform public sepolicy的策略进行扩展。与 vendor 共享的sepolicy 定义, 通常情况下, 意味着vendor 开发者可能为此新增一些权限. 一般system/vendor 共用的一些类型和属性的定义, neverallow 限制等会存放于此
2. private：与公有策略相反，被声明为私有策略的type或attribute对non-platform的策略作者是不可见的，仅限于system image 内部的使用, 不对vendor 开放，只会编译到system image 中
3. vendor: 仅能引用public 目录下的相关定义, 只会编译到vendor image 中. 但依旧可以对system image 里面的module 设定sepolicy(对应module 需要在public 下进行声明); 在很大程度上绕过了Google GTS 约束测试
4. mapping: 为兼容老版本的sepolicy 而导入, 只有在system image version > vendor version 的时候, 才可能被用到

##### Subject
通常就是进程或者内核的线程

##### Object
系统中所有可以被操作的资源，包括文件、进程、设备等等，定义在/bsp/kernel/kernel4.14/security/selinux/include/classmap.h
分解成四大类：文件相关的，网络相关的，System V IPC和杂项

##### Action
在操作系统的正常运行中会有大量的动作，因此 SELinux的设计者把这些动作根据客体类别（object class）进行分类，并且把每个类别所可以进行的动作都定义好。例如：file 类别定义了read、write、open 等权限，dir 类别定义了 add_name、remove_name、search 等权限。除了标准 SELinux 定义的类别，SEAndroid 还定义了特有的类别，包括 binder、zygote、property_service、service_manager等

##### avc规则
SEAndroid安全机制又称为是基于TE策略的安全机制。所有安全策略都存放在.te结尾的文件中，一般放在 /system/sepolicy/private/，厂商定制的一般放在/device/xxx/common/sepolicy/下

一个Type所具有的权限是通过allow语句来描述的，SEAndroid使用的是最小权限原则，只有通过allow语句声明的权限才是允许的，而其它没有通过allow语句声明的权限都是禁止

创建avc规则语句格式为：
```
allow scontext tcontext:class action
allow domains  type:class    permissions
```
Policy的意思为：在domains域中允许对标记为type类型的class执行permissions操作
例如：allow appdomain app_data_file:file rw_file_perms，所有应用程序域都允许读取和写入标记为app_data_file的文件

* allow：主体对客体执行允许的操作
* auditallow：即便允许操作也要记录访问决策信息(仍然需要有 allow 规则才允许)
* dontaudit：违反规则的决策信息也不记录(便于定位问题，已知此操作会被拒绝但不会引起真正问题)
* neverallow： 不允许主体对客体执行指定的操作

除了allow另外三个仅是检查及记录，并不赋予或禁止权限

##### Scontext
进程(Subject)的安全上下文的类型称为domain，使用命令 ps -z 可查看；文件（Object）的安全上下文中的类型称为file_type，使用 ls -Z 可以查看, 据 SELinux 规范，SContext 的格式为：  user:role:type:[range]
```
　　user：表示对象的所属用户，在 SEAndroid 中，目前仅定义一个 user（也就是 u）
　　role：表示活动对象的角色，在 SEAndroid 中，目前仅定义一个 role（也就是 r），具体是非活动对象（文件）为 object_r，活动对象（进程）为 r
　　type：表示对象的类型
　　range：表示对象的分级，如不同级别的资源需要对应级别的进程才能访问，一般都是 s0
```
在 Linux 系统中，一种是死的（比如文件、端口、系统属性等），一种是活的（进程），映射到软件层面的意思是：进程能发起动作，例如它能打开文件并操作它，而文件只能被进程操作
```
# 定义虚拟操作系统文件节点
genfscon proc/mtk_demo/demo_file u:object_r:demo_context:s0

# 定义网络端口的上下文
portcon tcp 8080 system_u:object_r:http_port_t
  
#：定义网络接口的上下文
netifcon eth0 system_u:object_r:netif_eth0_t system_u:object_r:netmsg_eth0_t

#：定义网络节点的上下文
nodecon 10.33.10.66 255.255.255.255 system_u:object_r:node_zeus_t;
```
1. seapp_contexts
用于声明APP创建数据目录的安全上下文，O上将该文件拆分为plat和nonplat 前缀的两个文件，plat前缀的文件用于声明system app，nonplat前缀的文件用于声明vendor app
```
user=system seinfo=platform domain=system_app type=system_app_data_file
user=shell seinfo=platform domain=shell name=com.android.shell type=shell_data_file
user=_app seinfo=platform domain=platform_app type=app_data_file levelFrom=user
user=_app domain=untrusted_app_25 type=app_data_file levelFrom=user
```
2. seinfo
可以从mac_permissions.xml查看，对于使用平台签名的App来说，它的seinfo为“platform”，即使用平台签名的App所运行在的进程domain为“platform_app”，并且它的数据文件的file_type为“platform_app_data_file”

1. file_contexts
用于声明文件的安全上下文，plat前缀的文件用于声明system、rootfs、data等与设备无关的文件。nonplat 用于声明vendor、data/vendor 等文件。虚拟文件系统的标识方式与普通的文件系统文件标识方式不一样，用genfscon来配置

4. service_contexts
用于声明java service 的安全上下文， O上将该文件拆分为plat和nonplat 前缀的两个文件，但nonplat前缀的文件并没有具体的内容（vendor和system java service不允许binder 操作）

5. property_contexts
用于声明属性的安全上下文，plat 前缀的文件用于声明system属性，nonplat前缀的文件用于声明vendor 属性。ril.开头的属性的安全上下文为u:object_r:radio_prop:s0，这意味着只有有权限访问Type为radio_prop的资源的进程才可以访问这些属性

6. hwservice_contexts
O上新增文件，用于声明HIDL service 安全上下文
```
android.hardware.vibrator::IVibrator                u:object_r:hal_vibrator_hwservice:s0
```

##### type
在 SELinux 体系中，所有的东西都要有 type。为了做到精确控制，必须对不同的东西定义不同的 type，而规则又都是使用 type 来进行控制的，有些 type 是有共性的（如vfat 和 fuse都属于 sd 卡的文件系统），为了同一目的，可能需要需要编写多条规则。因此 SELinux 的设计者引入了attribute，在定义 type 时可以指定 attribute。同一 type 可以指定多个attribute，不同 type 也可以指定同一个 attribute。在 SEAndroid 中，对于进程的 type 都会指定 domain 属性。对于文件的 type 都会指定 file_type属性，而可执行文件的 type 都会指定 exec_type 属性
```
# tr069_service域和netdomain, coredomain, domain域属性关联，这个 type 拥有domain(进程)属性，且是一个coredomain（核心进程）
type tr069_service, netdomain, coredomain, domain;

# tr069_service_exec类型和exec_type, file_type, system_file_type类型属性关联，这个 type拥有 file_type（文件）属性，且是一个 exec_type（可执行文件）
type tr069_service_exec, exec_type, file_type, system_file_type;
```
type有两个作用，定义（声明）并关联某个属性。可以把这两个作用分开，type定义，typeattribute进行关联
```
# 第一种方式：定义并关联
type httpd_user_content_t, file_type, httpdcontent;  

# 第二种方式：先定义，再关联
type httpd_user_content_t;
typeattribute httpd_user_content_t file_type, httpdcontent;
```

##### attribute
```
# All types used for devices.
attribute dev_type;

# All types used for processes.
attribute domain;

# All types used for filesystems.
attribute fs_type;

# All types used for files that can exist on a labeled fs.
# Do not use for pseudo file types.
attribute file_type;

# All types used for domain entry points.
attribute exec_type;

# All types used for property service
attribute property_type;

# All service_manager types created by system_server
attribute system_server_service;

# All domains that can override MLS restrictions.
# i.e. processes that can read up and write down.
attribute mlstrustedsubject;

# All types that can override MLS restrictions.
# i.e. files that can be read by lower and written by higher
attribute mlstrustedobject;

# All domains used for apps.
attribute appdomain;

# All domains used for apps with network access.
attribute netdomain;

# All domains used for binder service domains.
attribute binderservicedomain;
```

##### class
```
class filesystem #代表文件系统
class file      #代表普通文件
class dir       #代表目录
class fd        #代表文件描述符
class lnk_file  #代表链接文件
class chr_file  #代表字符设备文件
 
# network-related classes
class socket    
class tcp_socket
class udp_socket

class binder    #Android平台特有的binder
class zygote    #Android平台特有的zygote
```
##### service中的class类别
class core ，class main， class late_start，这三个“class”,只是标识这个服务的类型是哪一个，然后通过调用class_start, class_reset, class_stop等命令的时候，来统一操作同一类的服务。netd， ril-deamon服务被标识为class main, 那么当调用class_start main命令时，所有标识为main的服务都会被启动，这里的netd，ril-deamon就会被启动。对于core， late_start类的服务也是这样
1. core：系统最基本的服务，在C/C++层，如 adbd、logd、console、vold、ueventd、watchdogd等
2. main：framework层开始启动，除了netd、dhcpcd_eth0、wpa_supplicant、ril-daemon等，还有bootanim、media、zygote等
3. late_start：sdcard

##### pem_set
即permissions
```
common file {
      ioctl read write create getattr setattr lock relabelfrom relabelto
      append unlink link rename execute swapon quotaon mounton ...

# 继承common
class dir
inherits file
{
        add_name
        remove_name
        reparent
        search
        rmdir
        open
        audit_access
        execmod
}

# 不继承任何common，如
class binder
{
        impersonate
        call
        set_context_mgr
        transfer
}      
```

##### 类型转换
init进程拥有系统的最高权限，如果由Init进程fork，exec出来的进程默认是与init相同的权限，这肯定是不安全的。另一个场景是，由init生成的文件，默认也是init的读写权限，不方便其他低权限的文件进行访问
```
type_transition source_type target_type : class default_type;
```
1. 主体的域的转换
```
#  init_t 进程执行type为apache_exec_t的可执行文件时，新的进程转换到apache_t域, 但是却没有说明，有转换的权限，如果要上面的转换成功，还需要
type_transition init_t apache_exec_t : process apache_t;

#首先，得让init_t域中的进程能够执行type为apache_exec_t的文件
allow init_t apache_exec_t : file execute;

#然后，还得告诉SELiux，允许init_t做DT切换以进入apache_t域
allow init_t apache_t : process transition;

#最后，还得告诉SELinux，切换入口（对应为entrypoint权限）为执行pache_exec_t类型的文件
allow apache_t apache_exec_t : file entrypoint;
```   
2. 客体的转换
```
# passwd_t在tmp_t目录下创建文件时，该文件的类型转化为passwd_tmp_t。这里默认隐含了一个tmp_t类型dir，因为file的容器只能是个dir。同样的，如果要上面的语句运行成功，与需要有相应的权限说明
type_transition passwd_t tmp_t : file passwd_tmp_t;  

对应的必须有两个前提条件:
* The source domain needs permission to add file entries into the directory
这个process 必须有在这个目录下添加文件的权限.
 
* The source domain needs permission to create file entries
这个process 必须有在这个目录下创建以这个Security Context 为Label 的文件权限
```

##### neverallow
Google 新增的强制性约束主要是针对system/vendor 之间的IPC 约束，定义可以参考: /system/sepolicy/public/domain.te
Google neverallow 规则, 对SELinux Policy 的更新进行了限制, 以防止开发者过度开放权限，从而引发安全问题。并且通过CTS Test 检测开发者是否有违法相关的规则, 遇到与Google 定义相违背之处, 只能绕道, 或者修改设计

##### 案例
1. 定义一个init启动的service，demo_service，对应的执行文件是/system/bin/demo
```
(1) 创建一个demo.te在/device/mediatke/common/sepolicy 目录下
(2) 在demo.te中添加：demo的域（domain）类型定义
	type demo, domain;
(3) 在demo.te中添加：demo的可执行文件（客体）的类型定义
	type demo_exec, exec_type
(4) 在demo.te中添加：init启动service时类型转换声明，直接用一个宏，主要是用于把demo_exec（客体）转换成demo（进程域）	
	init_daemon_domain(demo)

init_daemon_domain：设置init转换到daemon域，可执行文件是xxx_exec
具体流程：init_daemon_domain(demo)，把$1=demo代换进去，相当于执行下面两条语句
# 定义旧的域转换成新的域的声明，直接把上面的参数代入到domain_auto_trans里相当于执行
domain_auto_trans(init, demo_exec, demo)
# 声明tmpfs的读写和转换权限，tmpfs是一些内存临时文件
tmpfs_domain(demo)

domain_auto_trans相当于执行下面两条语句
# 域转换的权限声明
domain_trans(init,demo_exec,demo)
#声明init域执行demo_exec可执行文件，新的域转换成demo域
type_transition init demo_exec:process demo;

(5) 绑定执行档 file_contexts 类型（安全上下文），由这个可执行文件启动起来的进程都是demo域里的
	/system/bin/demo  u:object_r:demo_exec:s0
(6) 根据demo需要访问的文件以及设备，定义其它的权限在demo.te中
```
2. 添加一个APP的节点访问权限
```
(1) 定义文件类型
device/mediatek/common/sepolicy/file.te 
type proc_mtk_demo, fs_type;

(2) 定义虚拟文件系统的文件安全上下文
device/mediatek/common/sepolicy/genfs_contexts 
genfscon proc /mtk_demo/current_demo u:object_r:proc_mtk_demo:s0

(3) 给予shell的进程读写权限，由/system/bin/sh启动的命令会与shell有同样的进程权限域
device/mediatek/common/sepolicy/shell.te 
allow shell proc_mtk_demo:file {open read write getattr};

(4) APP的读取权限
device/mediatek/common/sepolicy/system_app.te 
allow system_app proc_mtk_demo:file rw_file_perms;

(5) App使用方法之一
String[] cmd = {
		"/system/bin/sh", "-c", "echo " + st + " > " + "/proc/mtk_demo/current_demo",
};
Runtime.getRuntime().exec(cmd);
```
3. 定义一个init启动的服务cplc_info，对应的执行文件是/system/bin/cplc_info
```
# init.te
allow init cplc_info_exec:file { getattr open read execute };

# filecontexts
/system/bin/cplc_info     u:object_r:cplc_info_exec:s0

# init.rc
service cplc_info /system/bin/cplc_info
    group root
    user root
    oneshot

on property:persist.sys.cplc.enabled=0
    start cplc_info

# cplc_info.te
# cplc_info 
type cplc_info, domain;
type cplc_info_exec, system_file_type, exec_type, file_type;
typeattribute cplc_info coredomain;

init_daemon_domain(cplc_info)

allow cplc_info shell_exec:file {read open map execute getattr execute_no_trans};
allow cplc_info prod_file:dir  {search open read write remove_name add_name getattr rmdir};
allow cplc_info prod_file:file {read write unlink open create getattr setattr};
allow cplc_info system_file:file {open read map execute execute_no_trans getattr};
allow cplc_info nfc_device:chr_file {open read write getattr setattr ioctl};    
```

##### 关闭SeLinux
1. 修改kernel_cmdline 参数为BOARD_KERNEL_CMDLINE := androidboot.selinux=permissive
2. 在命令行执行 setenforce 0

##### 编译验证
在Andriod4.4至Andriod7.0，policy被编译合并为一个文件,放置boot.img或system.img。Andriod8.0及Android8.0+被分别编译，SOC和OEM被编译进vendor.img，如此需要在开机是，快速挂在/system和/vendro,在加载进kernel前合并policy。sepolicy 分离存储到system image 和 vendor image
编译方式：`mmm system/sepolicy/`

在编译完成后, 进行审查确认时, 可以查证:
```
/system/etc/selinux
/vendor/etc/selinux
```

##### 快速调试
1. 借助audit2allow生成缺失权限
```
安装方法：sudo apt-get install policycoreutils
使用方法：audit2allow -i *.log（此工具还有很多使用方法，具体其他用法请百度），这样即可根据 Log 自动生成 allow 语句
```
2. 将自己的可执行程序单独放入新建的rc
```
adb push cpcl_info.rc  system/etc/init/
```
开机后`setenforce 0`暂时关闭Selinux，再运行程序，可以尽可能多的暴露缺失的权限

3. 缺什么补什么
```
audit(0.0:67): avc: denied { write } for path="/dev/block/vold/93:96" dev="tmpfs" ino=1263 scontext=u:r:kernel:s0 tcontext=u:object_r:block_device:s0 tclass=blk_file permissive=0  
缺少什么权限：           { write }权限， 
谁缺少权限：             scontext=u:r:kernel:s0， 
对哪个文件缺少权限：   tcontext=u:object_r:block_device 
什么类型的文件：          tclass=blk_file  
解决方法：kernel.te 中增加：allow kernel block_device:blk_file write; 
```
4. 参考其他类似的TE，如可执行程序可参考bootanim.te